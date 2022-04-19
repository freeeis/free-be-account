const express = require(require('path').resolve('./') + "/node_modules/express");
const router = express.Router();

// change password
router.put('/',
    async (req, res, next) => {
        if (!req.body.phone) {
            res.makeError(300, 'Phone number is incorrect!', router.mdl);
            return next('route');
        }

        const phone = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.phone, res.app.modules.account.config.desKey);

        if (phone !== req.user.PhoneNumber || phone.length < 11) {
            res.makeError(301, 'Phone number is incorrect!', router.mdl);
            return next('route');
        }

        const result = await res.Module('sms').verify(phone, req.body.code);
        // app.logger.debug(cache.exportJson());

        if (!result) {
            res.makeError(402, 'Verification code is incorrect!', router.mdl);
            return next('route');
        }

        // update password
        if (!req.body.Password) {
            res.makeError(403, 'Please provide the password!', router.mdl);
            return next('route');
        }
        const password = res.app.modules.account.utils.crypto.encoder.desDecode(req.body.Password, res.app.modules.account.config.desKey);

        req.user.Password = res.app.modules.account.utils.encryptPwd(password, res.app.modules.account.config.pwdEncryptMethod || 'md5');
        await req.user.save();

        return next();
    }
);

module.exports = router;
