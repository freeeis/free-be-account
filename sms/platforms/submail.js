const axios = require('axios');
const crypto = require("crypto");

const client = axios.create({
    baseURL: 'https://api-v4.mysubmail.com',
    timeout: 308 * 1000,
    headers: {
        'Content-Type':'application/json',
    }
});

const sign = (appid, appkey, obj) => {
    // 排序obj并转为json字符串
    const bodyStr = Object.keys(obj).sort((a, b) => a > b ? 1 : (a < b ? -1 : 0)).map((k) => `${k}=${obj[k]}`).join('&');

    // md5
    var md5 = crypto.createHash('md5');

    return md5.update(`${appid}${appkey}${bodyStr}${appid}${appkey}`).digest('hex');
};

// https://www.mysubmail.com/documents/OOVyh
module.exports = {
    send: async function (k, p, v) {
        if (!k || !k.templateCode || !k.templateParamName) {
            throw new Error('SMS parameters not configured correctly for platform (Submail)');
        }

        var codeAndValue = {};

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

        const requestBody = {
            appid: k.appid,          // 在 SUBMAIL 应用集成中创建的短信应用 ID
            to: p,                   // 收件人手机号码
            project: k.templateCode, // 模版 ID
            timestamp: Math.floor(Date.now() / 1000),   // Timestamp UNIX 时间戳
            sign_type: 'md5',        // md5 or sha1 or normal
            sign_version: 2,         // signature 加密计算方式(当 sign_version 传 2 时，vars 参数不参与加密计算)
        };

        const signature = sign(k.appid, k.appkey, requestBody);

        return await client.post('/sms/xsend', {
            ...requestBody,
            signature,                          // 应用密匙或数字签名
            vars: JSON.stringify(codeAndValue), // 使用文本变量动态控制短信中的文本。
            // sms_signature: '',               // 自定义短信签名，如果忽略此参数，将使用模板的默认签名作为签名（此参数不参与加密计算）
        }).then(({data}) => {
            if (data.status === 'success') {
                return true;
            } else {
                console.error('SMS send error:', data.msg);
            }

            return false;            
        }).catch(() => {
            return false;
        });
    }
};