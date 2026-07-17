// Run once: node seed.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { Table, User } = require('./models');

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);

  const tables = [
    { tableNumber: 1, tableType: 'window', seatCapacity: 2 },
    { tableNumber: 2, tableType: 'window', seatCapacity: 2 },
    { tableNumber: 3, tableType: 'booth', seatCapacity: 4 },
    { tableNumber: 4, tableType: 'booth', seatCapacity: 4 },
    { tableNumber: 5, tableType: 'bar', seatCapacity: 1 },
    { tableNumber: 6, tableType: 'private', seatCapacity: 6 },
  ];

  for (const t of tables) {
    await Table.updateOne({ tableNumber: t.tableNumber }, { $set: t }, { upsert: true });
  }
  console.log(`Seeded ${tables.length} tables`);

  // Optional: create a staff account for testing the admin scanner
  const staffEmail = 'staff@noirandash.com';
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

  await mongoose.disconnect();
  console.log('Done.');
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
