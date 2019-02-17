const argon2 = require('argon2');

module.exports = (schema, options) => {
    schema.add({
        _pwd: {
            type: String
        },
        passwordChangedAt: {
            type: Date
        }
    });

    schema.virtual("password");

    schema.statics.resetPassword = async function (token, password) {
        // TODO: Review code
        const curToken = await this.getResetPasswordToken();

        if (await argon2.verify(curToken, token)) {
            user.password = password;

            await user.save();
        }
    }

    schema.methods.comparePassword = async function (password) {
        return argon2.verify(this._pwd, password);
    }

    schema.methods.changePassword = async function (oldPassword, password) {
        if (await this.comparePassword(oldPassword)) {
            this.password = password;

            await this.save();
        } else {
            throw new Error({ code: "invalidPassword", message: "Old password is invalid" });
        }
    }

    schema.methods.getResetPasswordToken = async function () {
        // TODO: Review code
        const salt = options.salt || "secret";

        return await argon2.hash(this._pwd, {
            salt
        });
    }

    schema.options.toJSON = {
        transform (doc, obj) {
            delete obj._pwd;
        }
    }

    schema.options.toObject = {
        transform (doc, obj) {
            delete obj._pwd;
        }
    }

    schema.pre("save", async function (next) {
        if (this.password) {            
            this._pwd = await argon2.hash(this.password);
            this.passwordChangedAt = new Date();
            this.password = null;
        }

        return next();
    });
}