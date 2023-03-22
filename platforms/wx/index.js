const axios = require('axios');
const { wx } = require('../../../../global');

const wxAgent = axios.create({
    baseURL: 'https://api.weixin.qq.com',
    timeout: 30 * 1000,
});

module.exports = {
    code2session: (code, mp) => {
        const appid = (mp && wx[mp] && wx[mp].appid) || wx.appid;
        const secret = (mp && wx[mp] && wx[mp].secret) || wx.secret;

        return wxAgent.get(`/sns/jscode2session?appid=${appid}&secret=${secret}&js_code=${code}&grant_type=authorization_code`);
    },
}