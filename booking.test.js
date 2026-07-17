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

function yesterdayDate() {
  const d = new Date();
  d.setDate(d.getDate() - 1);
  return d.toISOString().slice(0, 10);
}

describe('POST /api/bookings/create - validation', () => {
  let token;

  beforeEach(async () => {
    token = await registerAndLogin();
    await Table.create({ tableNumber: 1, tableType: 'window', seatCapacity: 2 });
  });

  it('rejects a booking for a past date', async () => {
    const res = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${token}`)
      .send({ tableNumber: 1, bookingDate: yesterdayDate(), timeSlot: '18:00', partySize: 2 });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/past/i);
  });

  it('rejects a time slot outside business hours / not on the grid', async () => {
    const res = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${token}`)
      .send({ tableNumber: 1, bookingDate: tomorrowDate(), timeSlot: '23:45', partySize: 2 });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/timeSlot must be one of/i);
  });

  it('rejects a malformed date string', async () => {
    const res = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${token}`)
      .send({ tableNumber: 1, bookingDate: '20-07-2026', timeSlot: '18:00', partySize: 2 });

    expect(res.status).toBe(400);
  });

  it('rejects a party size larger than table capacity', async () => {
    const res = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${token}`)
      .send({ tableNumber: 1, bookingDate: tomorrowDate(), timeSlot: '18:00', partySize: 10 });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/seats up to/i);
  });

  it('rejects booking for a nonexistent table', async () => {
    const res = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${token}`)
      .send({ tableNumber: 999, bookingDate: tomorrowDate(), timeSlot: '18:00', partySize: 2 });

    expect(res.status).toBe(404);
  });

  it('accepts a valid booking and returns a QR image', async () => {
    const res = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${token}`)
      .send({ tableNumber: 1, bookingDate: tomorrowDate(), timeSlot: '18:00', partySize: 2 });

    expect(res.status).toBe(201);
    expect(res.body.qrImage).toMatch(/^data:image\/png;base64,/);
    expect(res.body.booking.qrToken).toBeDefined();
  });
});

describe('POST /api/bookings/create - double-booking concurrency', () => {
  beforeEach(async () => {
    await Table.create({ tableNumber: 1, tableType: 'window', seatCapacity: 2 });
  });

  it('only allows ONE of two simultaneous requests for the same table/date/slot to succeed', async () => {
    const tokenA = await registerAndLogin('guestA@example.com');
    const tokenB = await registerAndLogin('guestB@example.com');
    const date = tomorrowDate();

    // Fire both requests at effectively the same time — this is the core
    // regression test for the race condition described in the ticket.
    const [resA, resB] = await Promise.all([
      request(app)
        .post('/api/bookings/create')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({ tableNumber: 1, bookingDate: date, timeSlot: '18:00', partySize: 2 }),
      request(app)
        .post('/api/bookings/create')
        .set('Authorization', `Bearer ${tokenB}`)
        .send({ tableNumber: 1, bookingDate: date, timeSlot: '18:00', partySize: 2 }),
    ]);

    const statuses = [resA.status, resB.status].sort();
    // Exactly one 201 (created) and one 409 (conflict) — never two 201s
    expect(statuses).toEqual([201, 409]);
  });

  it('allows a second booking once the first is cancelled', async () => {
    const tokenA = await registerAndLogin('guestA@example.com');
    const tokenB = await registerAndLogin('guestB@example.com');
    const date = tomorrowDate();

    const first = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ tableNumber: 1, bookingDate: date, timeSlot: '18:00', partySize: 2 });
    expect(first.status).toBe(201);

    await request(app)
      .patch(`/api/bookings/${first.body.booking._id}/cancel`)
      .set('Authorization', `Bearer ${tokenA}`);

    const second = await request(app)
      .post('/api/bookings/create')
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ tableNumber: 1, bookingDate: date, timeSlot: '18:00', partySize: 2 });
    expect(second.status).toBe(201);
  });
});
