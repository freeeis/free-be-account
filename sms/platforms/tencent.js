const tencentcloud = require("tencentcloud-sdk-nodejs-sms");

const smsClient = tencentcloud.sms.v20210111.Client;

// https://cloud.tencent.com/document/product/382/55981
module.exports = {
    send: async function (k, p, v) {
        if (!k || !k.SecretId || !k.SecretKey || !k.appid || !k.templateCode || !k.signName || !k.templateParamName) {
            throw new Error('SMS parameters not configured correctly for platform (Tencent)');
        }

        var paramValues = [];

        if (Array.isArray(k.templateParamName)) {
            for (let i = 0; i < k.templateParamName.length; i += 1) {
                const paramName = k.templateParamName[i];
                if (paramName && v && v[paramName]) {
                    paramValues.push(v[paramName]);
                }
            }
        } else {
            paramValues.push(v);
        }

        const client = new smsClient({
            credential: {
                secretId: k.SecretId,
                secretKey: k.SecretKey,
            },
            region: "ap-beijing",
            // 可选配置实例
            profile: {
                signMethod: "TC3-HMAC-SHA256", // 签名方法
                httpProfile: {
                    reqMethod: "POST", // 请求方法
                    reqTimeout: 30, // 请求超时时间，默认60s
                    headers: {
                        Action: 'SendSms',
                        Region: 'ap-beijing',
                        Version: '2021-01-11',
                        Language: 'zh-CN',
                    },
                },
            },
        });

        return await client
            .SendSms({
                PhoneNumberSet: [p],

                SmsSdkAppId: k.appid,
                TemplateId: k.templateCode,
                SignName: k.signName,

                TemplateParamSet: paramValues,
            })
            .then((response) => {
                const data = (response.SendStatusSet || [])[0] || {};

                if (data.Code === 'Ok') {
                    return true;
                } else {
                    console.error('SMS send error:', data.Code);
                }

                return false;
            })
            .catch((err) => {
                console.log('SMS send error:', err);
                return false;
            });
    }
};
