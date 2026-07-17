const request = require('supertest');
const { app } = require('../server');
const { Table } = require('../models');

async function registerAndLogin(email = 'guest@example.com') {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ fullName: 'Test Guest', email, password: 'SuperSecret123' });
  return res.body.token;
}

function tomorrowDate() {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  return d.toISOString().slice(0, 10);
}

async function createBooking(token, overrides = {}) {
  const res = await request(app)
    .post('/api/bookings/create')
    .set('Authorization', `Bearer ${token}`)
    .send({ tableNumber: 1, bookingDate: tomorrowDate(), timeSlot: '18:00', partySize: 2, ...overrides });
  return res.body.booking;
}

describe('Payments (mock mode — no RAZORPAY_KEY_ID configured in tests)', () => {
  let token;

  beforeEach(async () => {
    token = await registerAndLogin();
    await Table.create({ tableNumber: 1, tableType: 'window', seatCapacity: 4 });
  });

  it('booking starts out unpaid with a deposit amount attached', async () => {
    const booking = await createBooking(token);
    expect(booking.paymentStatus).toBe('unpaid');
    expect(booking.depositAmount).toBeGreaterThan(0);
  });

  it('creates a mock order when no gateway is configured', async () => {
    const booking = await createBooking(token);

    const res = await request(app)
      .post('/api/payments/create-order')
      .set('Authorization', `Bearer ${token}`)
      .send({ bookingId: booking._id });

    expect(res.status).toBe(200);
    expect(res.body.mock).toBe(true);
    expect(res.body.orderId).toMatch(/^mock_order_/);
    expect(res.body.amount).toBe(booking.depositAmount);
  });

  it('marks the booking paid after successful verification', async () => {
    const booking = await createBooking(token);
    const orderRes = await request(app)
      .post('/api/payments/create-order')
      .set('Authorization', `Bearer ${token}`)
      .send({ bookingId: booking._id });

    const verifyRes = await request(app)
      .post('/api/payments/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ bookingId: booking._id, orderId: orderRes.body.orderId, paymentId: 'mock_pay_123' });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.booking.paymentStatus).toBe('paid');
    expect(verifyRes.body.booking.paymentId).toBe('mock_pay_123');
  });

  it('rejects verification with a mismatched order id', async () => {
    const booking = await createBooking(token);
    await request(app)
      .post('/api/payments/create-order')
      .set('Authorization', `Bearer ${token}`)
      .send({ bookingId: booking._id });

    const res = await request(app)
      .post('/api/payments/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ bookingId: booking._id, orderId: 'mock_order_wrong', paymentId: 'mock_pay_123' });

    expect(res.status).toBe(400);
  });

  it('rejects payment routes without auth', async () => {
    const res = await request(app).post('/api/payments/create-order').send({ bookingId: '000000000000000000000000' });
    expect(res.status).toBe(401);
  });
});
