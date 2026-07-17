const mongoose = require('mongoose');
const { Schema } = mongoose;

/* ---------------------------- USER ---------------------------- */
const userSchema = new Schema(
  {
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, trim: true },
    passwordHash: { type: String, required: true },
    membershipTier: { type: String, enum: ['standard', 'gold', 'black'], default: 'standard' },
    role: { type: String, enum: ['member', 'staff'], default: 'member' },
  },
  { timestamps: true }
);

/* ---------------------------- SHOP SETTINGS ---------------------------- */
// Singleton document (there's only ever one row) holding the restaurant's
// public-facing details, so the frontend can display them without
// hardcoding text in components.
const shopSettingsSchema = new Schema(
  {
    shopName: { type: String, required: true },
    logoDescription: { type: String }, // text description; no image upload pipeline yet
    address: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    openingTime: { type: String, required: true }, // e.g. '10:00 AM'
    closingTime: { type: String, required: true }, // e.g. '11:00 PM'
    gstNumber: { type: String },
    totalTables: { type: Number, required: true },
  },
  { timestamps: true }
);

/* ---------------------------- TABLE ---------------------------- */
const tableSchema = new Schema(
  {
    tableNumber: { type: Number, required: true, unique: true },
    tableType: { type: String, enum: ['window', 'booth', 'bar', 'private'], required: true },
    seatCapacity: { type: Number, required: true },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

/* ---------------------------- BOOKING ---------------------------- */
const bookingSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    table: { type: Schema.Types.ObjectId, ref: 'Table', required: true },
    tableNumber: { type: Number, required: true }, // denormalized for fast display/QR payload
    bookingDate: { type: String, required: true }, // 'YYYY-MM-DD'
    timeSlot: { type: String, required: true }, // 'HH:mm' start time, e.g. '18:30'
    partySize: { type: Number, required: true },
    status: {
      type: String,
      enum: ['confirmed', 'cancelled', 'completed', 'no_show'],
      default: 'confirmed',
    },
    qrToken: { type: String, required: true, unique: true }, // signed payload encoded in the QR
    qrImage: { type: String }, // base64 data URL, generated once and cached
    checkedInAt: { type: Date, default: null },

    // ---- Online payment (reservation deposit) ----
    paymentStatus: { type: String, enum: ['unpaid', 'paid', 'refunded'], default: 'unpaid' },
    depositAmount: { type: Number, required: true }, // in paise (smallest INR unit)
    paymentOrderId: { type: String, default: null },
    paymentId: { type: String, default: null },
    paidAt: { type: Date, default: null },
  },
  { timestamps: true }
);

// This is what actually prevents double-booking: MongoDB rejects a second
// confirmed booking for the same table/date/slot at the DB layer, not just in app code.
bookingSchema.index(
  { table: 1, bookingDate: 1, timeSlot: 1 },
  {
    unique: true,
    partialFilterExpression: { status: 'confirmed' }, // cancelled bookings don't block the slot
  }
);

module.exports = {
  User: mongoose.model('User', userSchema),
  Table: mongoose.model('Table', tableSchema),
  Booking: mongoose.model('Booking', bookingSchema),
  ShopSettings: mongoose.model('ShopSettings', shopSettingsSchema),
};
