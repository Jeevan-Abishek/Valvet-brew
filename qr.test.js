const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { app, generateQrToken } = require('../server');
const { Table, User, Booking } = require('../models');

function staffToken(userId) {
  return jwt.sign({ sub: userId, email: 'staff@example.com', role: 'staff' }, process.env.JWT_SECRET, {
    expiresIn: '1d',
  });
}

async function createStaffUser() {
  const passwordHash = await bcrypt.hash('StaffPass123', 12);
  return User.create({ fullName: 'Staff', email: 'staff@example.com', passwordHash, role: 'staff' });
}

async function createGuestUser() {
  const passwordHash = await bcrypt.hash('GuestPass123', 12);
  return User.create({ fullName: 'Guest', email: 'guest@example.com', passwordHash });
}

// Directly inserts a confirmed booking so tests can control bookingDate/timeSlot
// precisely without depending on "today"/"tomorrow" logic in the booking route.
async function createConfirmedBooking({ table, user, bookingDate, timeSlot }) {
  const booking = await Booking.create({
    user: user._id,
    table: table._id,
    tableNumber: table.tableNumber,
    bookingDate,
    timeSlot,
    partySize: 2,
    qrToken: 'placeholder',
    depositAmount: 40000, // ₹400 for a party of 2, matches server's default deposit calc
  });
  const qrToken = generateQrToken({
    bookingId: booking._id.toString(),
    userId: user._id.toString(),
    tableNumber: table.tableNumber,
    bookingDate,
    timeSlot,
  });
  booking.qrToken = qrToken;
  await booking.save();
  return { booking, qrToken };
}

function timeSlotForMinutesFromNow(minutes) {
  const d = new Date(Date.now() + minutes * 60000);
  return {
    date: d.toISOString().slice(0, 10),
    slot: `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`,
  };
}

describe('POST /api/admin/verify-qr', () => {
  let staff, guest, table, adminToken;

  beforeEach(async () => {
    staff = await createStaffUser();
    guest = await createGuestUser();
    table = await Table.create({ tableNumber: 1, tableType: 'window', seatCapacity: 2 });
    adminToken = staffToken(staff._id.toString());
  });

  it('rejects a completely fabricated QR string', async () => {
    const res = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken: 'this-is-not-a-real-token' });

    expect(res.status).toBe(400);
    expect(res.body.access).toBe('denied');
  });

  it('rejects a tampered token (valid structure, wrong signature)', async () => {
    const { qrToken } = await createConfirmedBooking({
      table,
      user: guest,
      bookingDate: new Date().toISOString().slice(0, 10),
      timeSlot: '18:00',
    });

    // Flip a character in the base64 payload to simulate tampering
    const tampered = qrToken.slice(0, -2) + (qrToken.slice(-2) === 'AA' ? 'BB' : 'AA');

    const res = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken: tampered });

    expect(res.status).toBe(400);
    expect(res.body.access).toBe('denied');
  });

  it('denies entry if scanned more than the grace period before the slot starts', async () => {
    const future = timeSlotForMinutesFromNow(24 * 60); // 1 day from now — way outside the 15-min-early window
    const { qrToken } = await createConfirmedBooking({
      table,
      user: guest,
      bookingDate: future.date,
      timeSlot: future.slot,
    });

    const res = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken });

    expect(res.status).toBe(409);
    expect(res.body.access).toBe('denied');
    expect(res.body.error).toMatch(/too early/i);
  });

  it('denies entry once the reservation window has expired', async () => {
    const past = timeSlotForMinutesFromNow(-24 * 60); // 1 day ago — window closed long ago
    const { qrToken } = await createConfirmedBooking({
      table,
      user: guest,
      bookingDate: past.date,
      timeSlot: past.slot,
    });

    const res = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken });

    expect(res.status).toBe(409);
    expect(res.body.access).toBe('denied');
    expect(res.body.error).toMatch(/expired/i);
  });

  it('grants access for a valid, on-time QR code', async () => {
    const now = timeSlotForMinutesFromNow(0);
    const { qrToken } = await createConfirmedBooking({
      table,
      user: guest,
      bookingDate: now.date,
      timeSlot: now.slot,
    });

    const res = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken });

    expect(res.status).toBe(200);
    expect(res.body.access).toBe('granted');
    expect(res.body.booking.guestName).toBe('Guest');
  });

  it('denies a second check-in attempt with the same QR code', async () => {
    const now = timeSlotForMinutesFromNow(0);
    const { qrToken } = await createConfirmedBooking({
      table,
      user: guest,
      bookingDate: now.date,
      timeSlot: now.slot,
    });

    const first = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken });
    expect(first.body.access).toBe('granted');

    const second = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ qrToken });

    expect(second.status).toBe(409);
    expect(second.body.access).toBe('denied');
    expect(second.body.error).toMatch(/already checked in/i);
  });

  it('rejects a non-staff user from verifying a QR code at all', async () => {
    const guestAuthToken = jwt.sign(
      { sub: guest._id.toString(), email: guest.email, role: 'member' },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    const res = await request(app)
      .post('/api/admin/verify-qr')
      .set('Authorization', `Bearer ${guestAuthToken}`)
      .send({ qrToken: 'irrelevant' });

    expect(res.status).toBe(403);
  });
});
