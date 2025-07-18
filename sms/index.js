const fs = require('fs');
const path = require('path');
const AliyunCore = require('@alicloud/pop-core');
const nodemailer = require('nodemailer');

const submail = require('./platforms/submail');
const tencent = require('./platforms/tencent');

let global;

if (fs.existsSync(path.resolve(__dirname, '../../../global.js'))) {
    global = require('../../../global');
}

let MAIL_TRANS = {};

function _generateMSG (f = '4n') {
    if (typeof f !== 'string' || f.length < 2) {
        f = '4n';
    }

    let mLength = 0,
        mUseNumber = false,
        mUseChar = false;

    for (let i = 0; i < f.length; i += 1) {
        const fi = f[i].toLowerCase();

        switch (fi) {
            case 'n':
                mUseNumber = true;
                break;
            case 'c':
                mUseChar = true;
                break;
            default:
                mLength = mLength || Number(fi) || 0;
        }
    }

    mLength = mLength || 4;
    if (!mUseNumber && !mUseChar) {
        mUseNumber = true;
    }

    let charList = '';
    if (mUseNumber) charList = charList.concat('1234567890');
    if (mUseChar) charList = charList.concat('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');

    let msgValue = '';
    for (let i = 0; i < mLength; i += 1) {
        msgValue += charList[Math.floor(Math.random() * charList.length)]
    }

    return msgValue;
}

const _sms_lib = {
    aliyun: {
        send: async function (k, p, v) {
            if (!k || !k.accessKeyId || !k.secret || !k.signName || !k.templateCode || !k.templateParamName) {
                throw new Error('SMS parameters not configured correctly for platform (Aliyun)');
            }
            var client = new AliyunCore({
                accessKeyId: k.accessKeyId,
                accessKeySecret: k.secret,
                endpoint: 'https://dysmsapi.aliyuncs.com',
                apiVersion: '2017-05-25'
            });

            var codeAndValue = {};
            // codeAndValue[k.templateParamName] = v;

            if (Array.isArray(k.templateParamName)) {
                for (let i = 0; i < k.templateParamName.length; i += 1) {
                    const paramName = k.templateParamName[i];
                    if (paramName && v && v[paramName]) {
                        codeAndValue[paramName] = v[paramName];
                    }
                }
            } else {
                codeAndValue[k.templateParamName] = v;
            }

            var params = {
                "PhoneNumbers": p,
                "SignName": k.signName,
                "TemplateCode": k.templateCode,
                "TemplateParam": JSON.stringify(codeAndValue)
            }

            // params[k.templateParamName] = v;

            var requestOption = {
                method: 'POST'
            };

            const result = await client.request('SendSms', params, requestOption);

            return result && result.Code && result.Code === 'OK';
        }
    },
    eis: {
        send: async function () {
            return true;
        }
    },
    mail: {
        send: async function(k, p, v) {
            if(!k || !k.host || !k.secret || !k.mail || !k.from || !k.title) throw new Error('MMail configuration incorrect!');
            
            MAIL_TRANS[k.mail] = MAIL_TRANS[k.mail] || nodemailer.createTransport({ 
                host: k.host, 
                secureConnection: true,
                port: 465,
                secure: true, 
                auth: {
                    user: k.mail,
                    pass: k.secret,
                }
            });

            const result = await MAIL_TRANS[k.mail].sendMail({ 
                from: k.from,
                to: p,
                subject: typeof k.title === 'function' ? k.title(v) : k.title,
                html: typeof k.template === 'function' ? k.template(v) : k.template,
                envelope: {
                    from: k.from,
                    to: p,
                    cc: k.from,
                }
            });

            return result && result.accepted && result.accepted.length >= 1;
        }
    },
    submail,
    tencent,
}

module.exports = (app) => ({
    send: async function (p, value, c = true, t = 'default') {
        if (p.indexOf('@') > 0) {
            t = `${t}_mail`;
        }

        let keys = app.modules.account.config.sms.keys[t] || app.modules.account.config.sms.keys;

        if (!keys.platform) {
            keys = (global && global.sms && global.sms[t]);
        }
        
        // const keys = (global && global.sms && global.sms[t]) || app.modules.account.config.sms.keys[t] || app.modules.account.config.sms.keys;
        
        if (keys && keys.platform) {
            // should not send too frequent!
            const lastSentTime = await app.cache.get(`${p}_lastSentTime`);
            if (lastSentTime && (Date.now() - lastSentTime) < (keys.resentGap || (60 * 1000))) {
                throw new Error('Cannot send too frequently!');
            }

            if (_sms_lib[keys.platform]) {
                let sent = true;
                const v = keys.fixedCode || value;

                try {
                    sent = await _sms_lib[keys.platform].send(keys, p, v);
                } catch (ex) {
                    app.logger.error(JSON.stringify(ex));
                    return false;
                }
                if (sent) {
                    if (c) {
                        const cTime = keys.cacheTime || (5 * 60 * 1000)
                        await app.cache.put(p, v, cTime);
                        await app.cache.put(`${p}_lastSentTime`, Date.now(), cTime);
                    }
                    return true;
                } else {
                    return false;
                }
            } else {
                throw new Error(`SMS platform ${keys.platform} is not supported yet!`);
            }
        } else {
            throw new Error('SMS platform not configured!');
        }
    },
    /**
     * 
     * @param {String} p Phone number 
     * @param {String} f Random pattern, should be like '4nc', 4 means length, n means incude Numbers, c means include Chars.
     * @param {Boolean} c Cache or not
     * @param {String} t template, the key in the sms config
     */
    sendRandom: async function (p, f, c = true, t = 'default') {
        let v = _generateMSG(f);
        return await this.send(p, v, c, t);
    },
    verify: async function (p, v, del = true) {
        const cached = await app.cache.get(p);

        // clear cache if the code is correct
        if (del && cached === v) {
            await app.cache.del(p);
        }
        
        return cached === v;
    }
})