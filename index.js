const argon2 = require("argon2");
const JWTUtility = require("@abskmj/jwt-utility");
const MakeError = require("make-error");

module.exports = (schema, options) => {
    options.hash = options.hash || "HS256";
    options.issuer = options.issuer || "backend";
    options.subject = options.subject || "password";
    options.expiry = options.expiry || 24 * 60 * 60 * 1000;

    if (!options.secret) {
        throw new Error("JWT secret not provided.");
    }

    schema.add({
        _pwd: {
            type: String
        },
        passwordChangedAt: {
            type: Date
        }
    });

    schema.virtual("password");

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

    schema.methods.getResetPasswordToken = async function (claims = {}) {
        if (!claims.uid) claims.uid = this._id.toString();

        return JWTUtility
            .getFactory(options.hash)
            .setIssuer(options.issuer)
            .setSubject(options.subject)
            .setExpiry(options.expiry)
            .setClaims(claims)
            .sign(options.secret);
    }

    schema.statics.resetPassword = async function (token, password) {
        let data = JWTUtility.getParser()
            .validateIssuer(options.issuer)
            .validateSubject(options.subject)
            .parse(token, options.secret);
    
        const user = await this.findById(data.claims.uid);

        if (!user) throw new JWTError("invalidToken", "Given token is invalid");
        
        user.password = password;

        await user.save();
        
        return user;
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

    function JWTError (code, message, extra) {
        JWTError.super.call(this, message);

        this.code = code;
        this.message = message;
        this.extra = extra;
    }

    function PasswordError (code, message, extra) {
        JWTError.super.call(this, message);

        this.code = code;
        this.message = message;
        this.extra = extra;
    }

    MakeError(JWTError);
    MakeError(PasswordError);
}
