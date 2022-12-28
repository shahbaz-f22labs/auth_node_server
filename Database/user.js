
import mongoose from "mongoose";
import bcryptjs from 'bcryptjs';
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: String
    },
    password: {
        type: String,
        required: true
    }
});
userSchema.pre('save', function (next) {
    return __awaiter(this, void 0, void 0, function* () {
        this.password = bcryptjs.hash(this.password, 12);
        next();
    });
});
const userModel = mongoose.model("Users", userSchema);
export { userModel };
