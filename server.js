require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const QRCode = require('qrcode');

const { User, Table, Booking, ShopSettings } = require('./models');
const payments = require('./payments');

const app = express();

/* ------------------------------------------------------------------ */
/*  Startup checks                                                     */
/* ------------------------------------------------------------------ */
['MONGO_URI', 'JWT_SECRET', 'QR_SIGNING_SECRET'].forEach((key) => {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
});

app.use(helmet());
// CORS_ORIGIN can be a single URL or a comma-separated list (useful since
// Vercel gives a new URL on each fresh upload/deploy). If unset, allow all
// origins (fine for demo/dev; set a real list in production).
const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Requests with no origin (curl, server-to-server, mobile apps) are allowed.
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
  })
);
app.use(express.json());

if (require.main === module) {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch((err) => {
      console.error('MongoDB connection error:', err);
      process.exit(1);
    });
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */
const SLOT_DURATION_MINUTES = 90;
const SALT_ROUNDS = 12;
const CHECKIN_GRACE_MINUTES_BEFORE = 15; // guests can check in this many minutes before their slot starts
const CHECKIN_GRACE_MINUTES_AFTER = 30; // and up to this many minutes after their slot's official end
const MAX_ADVANCE_BOOKING_DAYS = 60; // stop people from booking absurdly far in the future by mistake
const DEPOSIT_PER_GUEST_INR = Number(process.env.DEPOSIT_PER_GUEST_INR || 200); // ₹200/guest reservation deposit

function calculateDepositPaise(partySize) {
  return DEPOSIT_PER_GUEST_INR * partySize * 100; // convert rupees -> paise
}

// 'YYYY-MM-DD' + 'HH:mm' -> Date object, interpreted in server local time
function combineDateAndSlot(bookingDate, timeSlot) {
  return new Date(`${bookingDate}T${timeSlot}:00`);
}

// Centralizes every rule a booking request must pass before it touches the DB.
// Returns a string error message, or null if the request is valid.
function validateBookingRequest({ bookingDate, timeSlot, partySize }) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(bookingDate)) {
    return 'bookingDate must be in YYYY-MM-DD format';
  }

  const slotStart = combineDateAndSlot(bookingDate, timeSlot);
  if (isNaN(slotStart.getTime())) {
    return 'Invalid bookingDate or timeSlot';
  }

  const validSlots = buildDaySlots();
  if (!validSlots.includes(timeSlot)) {
    return `timeSlot must be one of: ${validSlots.join(', ')}`;
  }

  const now = new Date();
  if (slotStart < now) {
    return 'You cannot book a time slot in the past';
  }

  const maxDate = new Date(now.getTime() + MAX_ADVANCE_BOOKING_DAYS * 24 * 60 * 60 * 1000);
  if (slotStart > maxDate) {
    return `Reservations can only be made up to ${MAX_ADVANCE_BOOKING_DAYS} days in advance`;
  }

  if (!Number.isInteger(partySize) || partySize < 1 || partySize > 20) {
    return 'partySize must be a whole number between 1 and 20';
  }

  return null;
}

function signAuthToken(user) {
  return jwt.sign({ sub: user._id.toString(), email: user.email, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
}

// Signs booking data so a QR code can't be fabricated by guessing an id.
function generateQrToken({ bookingId, userId, tableNumber, bookingDate, timeSlot }) {
  const payload = JSON.stringify({ bookingId, userId, tableNumber, bookingDate, timeSlot });
  const signature = crypto
    .createHmac('sha256', process.env.QR_SIGNING_SECRET)
    .update(payload)
    .digest('hex');
  // Base64-encode the whole thing so it's a clean single string to put in the QR
  return Buffer.from(JSON.stringify({ payload, signature })).toString('base64');
}

function verifyQrToken(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    const { payload, signature } = decoded;
    const expected = crypto
      .createHmac('sha256', process.env.QR_SIGNING_SECRET)
      .update(payload)
      .digest('hex');

    const valid =
      signature.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));

    if (!valid) return { valid: false };
    return { valid: true, data: JSON.parse(payload) };
  } catch (err) {
    return { valid: false };
  }
}

async function renderQrImage(token) {
  return QRCode.toDataURL(token, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 400,
    color: { dark: '#0D0B0A', light: '#F5EFE6' },
  });
}

/* ------------------------------------------------------------------ */
/*  Auth middleware                                                     */
/* ------------------------------------------------------------------ */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }
  try {
    const payload = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    req.user = { id: payload.sub, email: payload.email, role: payload.role };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Your session has expired. Please log in again.', code: 'TOKEN_EXPIRED' });
    }
    // Covers malformed tokens, bad signatures, tokens signed with a different secret, etc.
    return res.status(401).json({ error: 'Invalid authentication token', code: 'TOKEN_INVALID' });
  }
}

function requireStaff(req, res, next) {
  if (req.user.role !== 'staff') {
    return res.status(403).json({ error: 'Staff access required' });
  }
  next();
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many attempts. Please try again in a few minutes.' },
});

// Generous enough for a busy front desk scanning many real guests, but throttles
// someone trying to brute-force or spam fabricated QR strings.
const verifyQrLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many verification attempts. Please pause a moment.', access: 'denied' },
});

/* ==================================================================== */
/*  AUTH ROUTES                                                          */
/* ==================================================================== */

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'fullName, email, and password are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = await User.create({ fullName, email: email.toLowerCase(), phone, passwordHash });

    const token = signAuthToken(user);
    res.status(201).json({
      user: { id: user._id, fullName: user.fullName, email: user.email, membershipTier: user.membershipTier },
      token,
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong creating your account' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signAuthToken(user);
    res.json({
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        membershipTier: user.membershipTier,
        createdAt: user.createdAt,
      },
      token,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong logging you in' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Something went wrong fetching your profile' });
  }
});

/* ==================================================================== */
/*  TABLE ROUTES                                                         */
/* ==================================================================== */

// GET /api/tables
app.get('/api/tables', async (req, res) => {
  try {
    const tables = await Table.find({ isActive: true }).sort({ tableNumber: 1 });
    res.json({ tables });
  } catch (err) {
    console.error('Get tables error:', err);
    res.status(500).json({ error: 'Something went wrong fetching tables' });
  }
});

// GET /api/availability?date=2026-07-20&partySize=2
app.get('/api/availability', async (req, res) => {
  try {
    const { date, partySize = 1 } = req.query;
    if (!date) return res.status(400).json({ error: 'date query param is required (YYYY-MM-DD)' });

    const tables = await Table.find({ isActive: true, seatCapacity: { $gte: Number(partySize) } }).sort({
      tableNumber: 1,
    });

    const existingBookings = await Booking.find({ bookingDate: date, status: 'confirmed' }).select(
      'table timeSlot'
    );

    const slots = buildDaySlots(); // e.g. ['08:00','09:30',...]

    const availability = tables.map((table) => {
      const takenSlots = existingBookings
        .filter((b) => b.table.toString() === table._id.toString())
        .map((b) => b.timeSlot);

      return {
        table,
        slots: slots.map((slot) => ({ time: slot, available: !takenSlots.includes(slot) })),
      };
    });

    res.json({ date, availability });
  } catch (err) {
    console.error('Availability error:', err);
    res.status(500).json({ error: 'Something went wrong fetching availability' });
  }
});

function buildDaySlots() {
  const slots = [];
  let cursor = 8 * 60; // 08:00 in minutes
  const close = 20 * 60; // 20:00
  while (cursor + SLOT_DURATION_MINUTES <= close) {
    const h = String(Math.floor(cursor / 60)).padStart(2, '0');
    const m = String(cursor % 60).padStart(2, '0');
    slots.push(`${h}:${m}`);
    cursor += SLOT_DURATION_MINUTES;
  }
  return slots;
}

/* ==================================================================== */
/*  BOOKING ROUTES                                                       */
/* ==================================================================== */

// POST /api/bookings/create
app.post('/api/bookings/create', requireAuth, async (req, res) => {
  try {
    const { tableNumber, bookingDate, timeSlot, partySize } = req.body;

    if (!tableNumber || !bookingDate || !timeSlot || !partySize) {
      return res.status(400).json({ error: 'tableNumber, bookingDate, timeSlot, and partySize are required' });
    }

    const validationError = validateBookingRequest({ bookingDate, timeSlot, partySize });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const table = await Table.findOne({ tableNumber, isActive: true });
    if (!table) return res.status(404).json({ error: 'Table not found' });
    if (partySize > table.seatCapacity) {
      return res.status(400).json({ error: `This table seats up to ${table.seatCapacity} guests` });
    }

    // Availability check up front for a clean error message. The unique index
    // below is the real guarantee against race conditions — this is just UX.
    const conflict = await Booking.findOne({ table: table._id, bookingDate, timeSlot, status: 'confirmed' });
    if (conflict) {
      return res.status(409).json({ error: 'This table and time slot is no longer available' });
    }

    let booking;
    try {
      booking = await Booking.create({
        user: req.user.id,
        table: table._id,
        tableNumber: table.tableNumber,
        bookingDate,
        timeSlot,
        partySize,
        qrToken: 'pending', // placeholder, replaced right after we have the _id
        depositAmount: calculateDepositPaise(partySize),
      });
    } catch (err) {
      // 11000 = duplicate key -> someone else grabbed this exact slot a moment ago
      if (err.code === 11000) {
        return res.status(409).json({ error: 'This table and time slot was just booked. Please choose another.' });
      }
      throw err;
    }

    const qrToken = generateQrToken({
      bookingId: booking._id.toString(),
      userId: req.user.id,
      tableNumber: table.tableNumber,
      bookingDate,
      timeSlot,
    });
    const qrImage = await renderQrImage(qrToken);

    booking.qrToken = qrToken;
    booking.qrImage = qrImage;
    await booking.save();

    res.status(201).json({ booking, qrImage });
  } catch (err) {
    console.error('Create booking error:', err);
    res.status(500).json({ error: 'Something went wrong creating your reservation' });
  }
});

// GET /api/bookings/me
app.get('/api/bookings/me', requireAuth, async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.user.id }).sort({ bookingDate: -1, timeSlot: -1 });
    res.json({ bookings });
  } catch (err) {
    console.error('Get my bookings error:', err);
    res.status(500).json({ error: 'Something went wrong fetching your reservations' });
  }
});

// PATCH /api/bookings/:id/cancel
app.patch('/api/bookings/:id/cancel', requireAuth, async (req, res) => {
  try {
    const booking = await Booking.findOneAndUpdate(
      { _id: req.params.id, user: req.user.id, status: 'confirmed' },
      { status: 'cancelled' },
      { new: true }
    );
    if (!booking) return res.status(404).json({ error: 'Active reservation not found' });
    res.json({ booking });
  } catch (err) {
    console.error('Cancel booking error:', err);
    res.status(500).json({ error: 'Something went wrong cancelling your reservation' });
  }
});

/* ==================================================================== */
/*  PAYMENT ROUTES (reservation deposit)                                 */
/* ==================================================================== */

// POST /api/payments/create-order   { bookingId }
// Creates a payment order for that booking's deposit. Returns the order id
// and Razorpay key so the frontend can open the checkout widget. When no
// Razorpay credentials are configured on the server, a mock order is
// returned instead so the flow can still be exercised end-to-end locally.
app.post('/api/payments/create-order', requireAuth, async (req, res) => {
  try {
    const { bookingId } = req.body;
    if (!bookingId) return res.status(400).json({ error: 'bookingId is required' });

    const booking = await Booking.findOne({ _id: bookingId, user: req.user.id });
    if (!booking) return res.status(404).json({ error: 'Reservation not found' });
    if (booking.status !== 'confirmed') {
      return res.status(409).json({ error: `Reservation is ${booking.status}, cannot take payment` });
    }
    if (booking.paymentStatus === 'paid') {
      return res.status(409).json({ error: 'This reservation has already been paid for' });
    }

    const order = await payments.createOrder({
      amountInPaise: booking.depositAmount,
      receipt: booking._id.toString(),
      notes: { bookingId: booking._id.toString(), tableNumber: booking.tableNumber },
    });

    booking.paymentOrderId = order.orderId;
    await booking.save();

    res.json({
      orderId: order.orderId,
      amount: order.amount,
      currency: order.currency,
      keyId: order.keyId, // null in mock mode
      mock: order.mock,
    });
  } catch (err) {
    console.error('Create payment order error:', err);
    res.status(500).json({ error: 'Something went wrong starting your payment' });
  }
});

// POST /api/payments/verify   { bookingId, orderId, paymentId, signature }
// Called after the checkout widget (or mock modal) reports success.
// Verifies the payment signature server-side before marking the deposit paid —
// the client's word alone is never trusted.
app.post('/api/payments/verify', requireAuth, async (req, res) => {
  try {
    const { bookingId, orderId, paymentId, signature } = req.body;
    if (!bookingId || !orderId || !paymentId) {
      return res.status(400).json({ error: 'bookingId, orderId, and paymentId are required' });
    }

    const booking = await Booking.findOne({ _id: bookingId, user: req.user.id });
    if (!booking) return res.status(404).json({ error: 'Reservation not found' });
    if (booking.paymentOrderId !== orderId) {
      return res.status(400).json({ error: 'This order does not match the reservation' });
    }
    if (booking.paymentStatus === 'paid') {
      return res.json({ booking }); // already paid, idempotent
    }

    const valid = payments.verifyPaymentSignature({ orderId, paymentId, signature });
    if (!valid) {
      return res.status(400).json({ error: 'Payment could not be verified' });
    }

    booking.paymentStatus = 'paid';
    booking.paymentId = paymentId;
    booking.paidAt = new Date();
    await booking.save();

    res.json({ booking });
  } catch (err) {
    console.error('Verify payment error:', err);
    res.status(500).json({ error: 'Something went wrong confirming your payment' });
  }
});

/* ==================================================================== */
/*  ADMIN ROUTES                                                         */
/* ==================================================================== */

// POST /api/admin/verify-qr   { qrToken: "<base64 string from QR>" }
app.post('/api/admin/verify-qr', verifyQrLimiter, requireAuth, requireStaff, async (req, res) => {
  try {
    const { qrToken } = req.body;
    if (!qrToken) return res.status(400).json({ error: 'qrToken is required', access: 'denied' });

    const { valid, data } = verifyQrToken(qrToken);
    if (!valid) {
      return res.status(400).json({ error: 'Invalid or tampered QR code', access: 'denied' });
    }

    const booking = await Booking.findById(data.bookingId).populate('user', 'fullName email membershipTier');
    if (!booking) {
      return res.status(404).json({ error: 'Reservation not found', access: 'denied' });
    }
    if (booking.status !== 'confirmed') {
      return res.status(409).json({ error: `Reservation is ${booking.status}, not confirmed`, access: 'denied' });
    }
    if (booking.checkedInAt) {
      return res.status(409).json({
        error: `Already checked in at ${booking.checkedInAt.toLocaleTimeString()}`,
        access: 'denied',
      });
    }

    // Valid QR signature does NOT mean valid right now — a guest could show up a
    // week early or a week late with a perfectly legitimate, unaltered QR code.
    const slotStart = combineDateAndSlot(booking.bookingDate, booking.timeSlot);
    const slotEnd = new Date(slotStart.getTime() + SLOT_DURATION_MINUTES * 60000);
    const windowStart = new Date(slotStart.getTime() - CHECKIN_GRACE_MINUTES_BEFORE * 60000);
    const windowEnd = new Date(slotEnd.getTime() + CHECKIN_GRACE_MINUTES_AFTER * 60000);
    const now = new Date();

    if (now < windowStart) {
      return res.status(409).json({
        error: `Too early — this reservation is for ${booking.bookingDate} at ${booking.timeSlot}`,
        access: 'denied',
      });
    }
    if (now > windowEnd) {
      return res.status(409).json({
        error: 'This reservation window has expired',
        access: 'denied',
      });
    }

    booking.checkedInAt = new Date();
    await booking.save();

    res.json({
      access: 'granted',
      message: 'Access Granted',
      booking: {
        id: booking._id,
        guestName: booking.user.fullName,
        membershipTier: booking.user.membershipTier,
        tableNumber: booking.tableNumber,
        bookingDate: booking.bookingDate,
        timeSlot: booking.timeSlot,
        partySize: booking.partySize,
        checkedInAt: booking.checkedInAt,
      },
    });
  } catch (err) {
    console.error('Verify QR error:', err);
    res.status(500).json({ error: 'Something went wrong verifying this code', access: 'denied' });
  }
});

// GET /api/shop-settings — public, read-only restaurant details for the frontend to display
app.get('/api/shop-settings', async (req, res) => {
  try {
    const settings = await ShopSettings.findOne();
    if (!settings) return res.status(404).json({ error: 'Shop settings not configured yet' });
    res.json({ settings });
  } catch (err) {
    console.error('Get shop settings error:', err);
    res.status(500).json({ error: 'Something went wrong fetching shop settings' });
  }
});

// GET /api/admin/seed?secret=... — one-time setup helper.
// Populates shop settings, the 30 tables, a staff account, a demo member,
// and a demo booking, matching the project's sample data. Protected by
// SEED_SECRET (set in .env) so a random visitor can't trigger it. Safe to
// call more than once — every write here is an upsert / "skip if exists".
app.get('/api/admin/seed', async (req, res) => {
  try {
    if (!process.env.SEED_SECRET || req.query.secret !== process.env.SEED_SECRET) {
      return res.status(403).json({ error: 'Invalid or missing secret' });
    }

    await ShopSettings.updateOne(
      {},
      {
        $set: {
          shopName: 'Urban Spice Bistro',
          logoDescription: 'Modern circular logo featuring a fork & spoon with the initials USB in emerald green and gold',
          address: 'No. 42, Anna Salai, T. Nagar, Chennai – 600017, Tamil Nadu, India',
          phone: '+91 8608159011',
          email: 'jeevanabishek278@gmail.com',
          openingTime: '10:00 AM',
          closingTime: '11:00 PM',
          gstNumber: '33AABCU9603R1ZV',
          totalTables: 30,
        },
      },
      { upsert: true }
    );

    const TYPE_CYCLE = ['window', 'booth', 'bar', 'private'];
    const CAPACITY_BY_TYPE = { window: 2, booth: 4, bar: 1, private: 6 };
    const tables = [];
    for (let n = 1; n <= 30; n += 1) {
      tables.push({
        tableNumber: n,
        tableType: TYPE_CYCLE[(n - 1) % TYPE_CYCLE.length],
        seatCapacity: CAPACITY_BY_TYPE[TYPE_CYCLE[(n - 1) % TYPE_CYCLE.length]],
      });
    }
    const t12 = tables.find((t) => t.tableNumber === 12);
    t12.tableType = 'booth';
    t12.seatCapacity = 4;
    for (const t of tables) {
      await Table.updateOne({ tableNumber: t.tableNumber }, { $set: t }, { upsert: true });
    }

    const staffEmail = 'staff@urbanspicebistro.com';
    let staffCreated = false;
    if (!(await User.findOne({ email: staffEmail }))) {
      const passwordHash = await bcrypt.hash('StaffPass123', SALT_ROUNDS);
      await User.create({ fullName: 'Front Desk Staff', email: staffEmail, passwordHash, role: 'staff' });
      staffCreated = true;
    }

    const customerEmail = 'rahul.sharma@example.com';
    let customer = await User.findOne({ email: customerEmail });
    let customerCreated = false;
    if (!customer) {
      const passwordHash = await bcrypt.hash('DemoPass123', SALT_ROUNDS);
      customer = await User.create({
        fullName: 'Rahul Sharma',
        email: customerEmail,
        phone: '+91 9876543210',
        passwordHash,
        membershipTier: 'gold',
        role: 'member',
      });
      customerCreated = true;
    } else if (customer.membershipTier !== 'gold') {
      customer.membershipTier = 'gold';
      await customer.save();
    }

    const bookingDate = '2026-07-17';
    const timeSlot = '19:30';
    const partySize = 4;
    const tableNumber = 12;
    const table = await Table.findOne({ tableNumber });
    let bookingCreated = false;

    const existingBooking = await Booking.findOne({ table: table._id, bookingDate, timeSlot, status: 'confirmed' });
    if (!existingBooking) {
      const booking = await Booking.create({
        user: customer._id,
        table: table._id,
        tableNumber,
        bookingDate,
        timeSlot,
        partySize,
        status: 'confirmed',
        qrToken: 'pending',
        paymentStatus: 'paid',
        depositAmount: 50000,
        paymentOrderId: 'ORD-20260717-8F3A91D2',
        paymentId: 'demo_pay_8F3A91D2',
        paidAt: new Date(),
      });

      const qrToken = generateQrToken({
        bookingId: booking._id.toString(),
        userId: customer._id.toString(),
        tableNumber,
        bookingDate,
        timeSlot,
      });
      const qrImage = await QRCode.toDataURL(qrToken, { errorCorrectionLevel: 'M', margin: 2, width: 400 });
      booking.qrToken = qrToken;
      booking.qrImage = qrImage;
      await booking.save();
      bookingCreated = true;
    }

    res.json({
      status: 'ok',
      tablesSeeded: tables.length,
      staffCreated,
      customerCreated,
      bookingCreated,
      message: 'Database seeded successfully. You can now reserve tables on the site.',
    });
  } catch (err) {
    console.error('Seed error:', err);
    res.status(500).json({ error: 'Seeding failed', details: err.message });
  }
});

/* ------------------------------------------------------------------ */
app.get('/api/health', (req, res) => res.json({ status: 'ok', paymentsMode: payments.isRazorpayConfigured ? 'razorpay' : 'mock' }));

app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong on our end' });
});

const PORT = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`The Velvet Brew API (MongoDB) running on port ${PORT}`));
}

module.exports = { app, generateQrToken, verifyQrToken, combineDateAndSlot };
