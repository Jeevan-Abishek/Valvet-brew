// Run once: node seed.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { Table, User, Booking, ShopSettings } = require('./models');

// Same signing logic as server.js's generateQrToken, duplicated here so the
// seed script has no dependency on the Express app (and can't accidentally
// start a server or trigger its own mongoose.connect()).
function generateQrToken({ bookingId, userId, tableNumber, bookingDate, timeSlot }) {
  const payload = JSON.stringify({ bookingId, userId, tableNumber, bookingDate, timeSlot });
  const signature = crypto
    .createHmac('sha256', process.env.QR_SIGNING_SECRET)
    .update(payload)
    .digest('hex');
  return Buffer.from(JSON.stringify({ payload, signature })).toString('base64');
}

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);

  /* -------------------- Shop settings -------------------- */
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
        gstNumber: '33AABCU9603R1ZV', // sample GSTIN for development/demo
        totalTables: 30,
      },
    },
    { upsert: true }
  );
  console.log('Shop settings seeded: Urban Spice Bistro');

  /* -------------------- Tables (30 total) -------------------- */
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
  // Table 12 is called out with specific details (seats 4) — force it to a booth.
  const t12 = tables.find((t) => t.tableNumber === 12);
  t12.tableType = 'booth';
  t12.seatCapacity = 4;

  for (const t of tables) {
    await Table.updateOne({ tableNumber: t.tableNumber }, { $set: t }, { upsert: true });
  }
  console.log(`Seeded ${tables.length} tables (T-12 = booth, seats 4)`);

  /* -------------------- Staff account (for admin scanner) -------------------- */
  const staffEmail = 'staff@urbanspicebistro.com';
  const existingStaff = await User.findOne({ email: staffEmail });
  if (!existingStaff) {
    const passwordHash = await bcrypt.hash('StaffPass123', 12);
    await User.create({
      fullName: 'Front Desk Staff',
      email: staffEmail,
      passwordHash,
      role: 'staff',
    });
    console.log(`Created staff account: ${staffEmail} / StaffPass123`);
  }

  /* -------------------- Demo customer -------------------- */
  const customerEmail = 'rahul.sharma@example.com';
  let customer = await User.findOne({ email: customerEmail });
  if (!customer) {
    const passwordHash = await bcrypt.hash('DemoPass123', 12);
    customer = await User.create({
      fullName: 'Rahul Sharma',
      email: customerEmail,
      phone: '+91 9876543210',
      passwordHash,
      membershipTier: 'gold',
      role: 'member',
    });
    console.log(`Created demo customer: ${customerEmail} / DemoPass123`);
  } else if (customer.membershipTier !== 'gold') {
    customer.membershipTier = 'gold';
    await customer.save();
  }

  /* -------------------- Demo booking (matches provided sample data) -------------------- */
  const bookingDate = '2026-07-17';
  const timeSlot = '19:30'; // 7:30 PM - 9:00 PM
  const partySize = 4;
  const tableNumber = 12;

  const table = await Table.findOne({ tableNumber });

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
      depositAmount: 50000, // ₹500 in paise
      paymentOrderId: 'ORD-20260717-8F3A91D2',
      paymentId: 'demo_pay_8F3A91D2',
      paidAt: new Date(),
    });

    // The QR token is cryptographically signed (HMAC with QR_SIGNING_SECRET),
    // so it can't just be the literal string from the sample data — it's
    // regenerated here the same way server.js does it, keeping the demo
    // booking scannable and valid in the admin app.
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

    console.log('Seeded demo booking for Rahul Sharma at table T-12, 17 Jul 2026, 7:30–9:00 PM (Confirmed)');
  } else {
    console.log('Demo booking already exists for that table/date/slot — skipped');
  }

  await mongoose.disconnect();
  console.log('Done.');
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
