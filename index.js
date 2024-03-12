// 三种方式注册，简单用户名密码，不需要验证，只要不重复即可
// 手机号注册，验证码
// 邮箱注册，验证

// nodemailer send email
var svgCaptcha = require('svg-captcha');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const {v1: uuidv1} = require('uuid');
const crypto = require("./crypto");
const { clearPermission, getPermissionPathList, verifyPassword, encryptPwd } = require('./utils');
const { AccountAuditStatus } = require('./enum');
const sms = require('./sms');
const wx = require('./platforms/wx/index');

let __app_service_list_saved = false;
let __saved_service_list;

const __getServiceList = async (res, filter = { Enabled: true }) => {
    // add app.serviceList into db if not yet
    if (!__app_service_list_saved) {
        await res.app.modules.account.utils.saveServiceList(res.app);
        __app_service_list_saved = true;
    } else if (!filter){
        return __saved_service_list;
    }

    const allPerms = await res.app.models.permission.find(filter);

    const permList = {};
    if (allPerms && allPerms.length > 0) {
        // create permission object
        allPerms.forEach(doc => {
            if (!doc.Path) return;

            const pathList = doc.Path.split('/');
            let permo = permList;
            for (let i = 0; i < pathList.length; i += 1) {
                const pl = pathList[i];
                if (!pl) continue;
                permo[pl] = permo[pl] || {};
                permo = permo[pl];

                if (i >= pathList.length - 1) {
                    Object.assign(permo, {
                        Title: doc.Title,
                        Description: doc.Description,
                        Index: doc.Index,
                    },
                    // TODO: only add data scope when no filter provided, correct?
                    filter ? {} : {
                        Scope: filter ? undefined: doc.Scope.map(sc => {
                            const dso = res.app.getContainerContent('DataScope').find(ds => ds.Name === sc.Name);
                            return dso ? {
                                Label: dso.Label || '',
                                Field: `${sc.Name}`,
                                Type: dso.Component || 'Select',
                                Options: dso.Options || [],
                                Multiple: dso.Multiple || false,
                            } : {};
                        })
                    })
                }
            }
        })
    }

    if (!filter) {
        __saved_service_list = permList;
    }

    return permList;
}

/**
 * 检验接口调用权限。
 *
 * @param app
 * @param user_permission
 * @param api_path
 * @returns {boolean}
 */
const verify_api_permission = async (app, mdl, user, api_path) => {
    const service_list = await __getServiceList({ app });
    if (!service_list || Object.keys(service_list).length <= 0) return false;

    // give any other modules a chance to control user permission.
    const cachedPerm = await app.cache.get(`perm_ctrl_${user.id}`);
    if(cachedPerm) {
        user.Permission = cachedPerm;
    } else {
        const permControlList = app.getContainerContent('PermissionControl');
        for (let i = 0; i < permControlList.length; i += 1) {
            const pc = permControlList[i];
    
            if(typeof pc === 'function') {
                await pc(user);
            }
        }

        app.cache.put(`perm_ctrl_${user.id}`, user.Permission);
    }

    const user_permission = user ? user.Permission : {};

    if (user_permission === '*') return true;

    if (!service_list) return false;
    if (!user_permission) return false;

    // hooks from other modules
    const customizedList = ((mdl.config && mdl.config['customizeControlList']) || []);
    for (let i = 0; i < customizedList.length; i += 1) {
        const cl = customizedList[i];

        if (typeof cl !== 'object') continue;
        if (!cl.pattern || !cl.replace) continue;

        if (typeof cl.pattern === 'string')
            api_path = api_path.replace(cl.pattern, cl.replace);

        if (typeof cl.pattern === 'object')
            api_path = api_path.replace(new RegExp(cl.pattern), cl.replace);
    }

    const qIndex = api_path.indexOf('?')
    if (qIndex > 0) api_path = api_path.substr(0, qIndex)
    if (api_path.startsWith('/api/')) api_path = api_path.slice('/api/'.length);
    if (api_path.startsWith('api/')) api_path = api_path.slice('api/'.length);
    const api_service_list = api_path.split('/');
    let service = service_list;
    let user_service = typeof user_permission === 'string' ? JSON.parse(user_permission.replace(/'/g, '"')) : user_permission;

    // check permission
    for (let i = 0; i < api_service_list.length; ++i) {
        const api_service = api_service_list[i];

        if (api_service !== '') {
            if (service[api_service]) {
                if (!user_service[api_service]) {
                    return false;
                }

                service = service[api_service];
                user_service = user_service[api_service];
            }
            else {
                return true;
            }
        }
    }

    return true; // TODO: secure enough??
}


async function clear_cache_token_by_user_id (app, id) {
    if (!id) return;

    const cacheKeys = await app.cache.keys();
    if (cacheKeys && cacheKeys.length) {
        for (let i = 0; i < cacheKeys.length; i += 1) {
            const k = cacheKeys[i];

            let value = await app.cache.get(k);
            if (value && value.userId && value.userId === id)
                await app.cache.del(k);
        }
    }
}

async function generate_new_access_token_pwd (app, userId, oldToken, keepToken = '', isWx = false) {
    let uuid = keepToken || uuidv1();

    // remove the old one from cache
    app.cache.del(oldToken);
    // cache.del(oldToken);
    await clear_cache_token_by_user_id(app, userId);

    // add the new one to the cache

    app.cache.put(uuid, { userId: userId, type: isWx ? 'wx' : 'pwd' }, app.config['cacheTimeout']);
    // cache.put(uuid, { userId: userId, type: 'pwd' }, app.config['cacheTimeout']);

    return uuid;
}

module.exports = (app) => ({
    sms: sms(app),
    AccountAuditStatus,
    config: {
        routeRoot: 'account',
        asRouteService: true,

        dependencies: [
            'core-modules'
        ],
        
        defaultPassword: '12345678',
        subAccountsHaveSameDateScope: true,
        subAccountsHaveSubAccountsPermission: false,

        accountRequireAudit: true,
        accountDefaultPermissions: {},
        accountDefaultPassword: '12345678',
        accountDefaultPasswordRandom: false,
        accountDefaultPasswordRandomLength: 6,
        // accountDefaultPermissions: [
        //     // could from system config
        //     // {
        //     //     condition: {},
        //     //     permission: {}
        //     // }
        // ],
        whiteList: [],
        userWhiteList: [],
        customizeControlList: [],
        keepTokenAccounts: ['demo'],
        strategy: 'local',
        defaultAccountName: 'admin',
        defaultAccountPwd: 'adminadmin',
        pwdEncryptMethod: ['sha1', 'bcrypt', 'md5'],
        desKey: 'eis,is,s,2020',

        // force to reset password period (days). 0 to disable
        forceResetPwd: 0,

        dataScopes: [],
        permissionControls: [],
        captcha: {
            cache: 5 * 60 * 1000,
            login: false,
            register: false,
            recover: false,
            ignoreCase: true,
            options: {},
        },

        permFields: [
            {
                Type: 'Category',
                Label: '权限定义信息',
            },
            {
                Name: 'Index',
                Label: '排序号',
                Type: 'Number',
            },
            {
                Name: 'Name',
                Label: '数据名称',
                Type: 'String',
            },
            {
                Name: 'Title',
                Label: '显示名称',
                Type: 'String',
            },
            {
                Name: 'Description',
                Label: '说明',
                Type: 'Text',
            },
        ],
        
        infoStepsDefinition: [
            {
                Name: '用户信息',
                Index: 1,
                Description: [{ Status: '1', Description: '已填写' }, { Status: '-1', Description: '未填写' }, { Status: '0', Description: '未填写' }],
                Actions: [
                    {
                        Label: '保存',
                        Action: 'save',
                    },
                    {
                        Label: '提交审核',
                        Action: 'submit',
                    },
                    {
                        Label: '修改',
                        Action: 'edit',
                    },
                ],
                Fields: [
                    {
                        Type: 'Category',
                        Label: '账号信息',
                    },
                    {
                        Type: 'String',
                        Label: '登录手机号',
                        Name: 'PhoneNumber',
                        Index: 1,
                        ReadOnly: true,
                    },
                    {
                        Type: 'Category',
                        Label: '用户信息',
                    },
                    {
                        Type: 'String',
                        Label: '姓名',
                        Name: 'Profile.Name',
                        Index: 1,
                    },
                    {
                        Type: 'String',
                        Label: '昵称',
                        Name: 'Profile.NickName',
                        Index: 2,
                    },
                    {
                        Type: 'String',
                        Label: '邮箱',
                        Name: 'Profile.Email',
                        Index: 3,
                    },
                    {
                        Type: 'String',
                        Label: '职务',
                        Name: 'Profile.Title',
                        Index: 4,
                    },
                ],
            },
        ],

        sms: {
            platform: '',
            keys: {}
        },
    },
    data: {
        account: {
            // account could have sub accounts
            Parent: { type: 'ID', refer: 'account' },

            // local login user name and password
            PhoneNumber: { type: 'String', unique: true, sparse: true },
            UserName: { type: 'String', unique: true, sparse: true },
            Password: { type: 'String' },

            // 3rd party login token
            Secret: { type: 'String', unique: true, sparse: true },

            // more info saved in profile
            Profile: { type: 'Object' },

            Enabled: { type: 'Boolean', default: true },

            PwdUpdatedAt: { type: 'Date' },

            Permission: { type: 'Object', default: {} },

            // Audit status
            Status: { type: 'String' },

            Org: { type: 'ID', refer: 'organization' },

            Labels: { type: 'Array', default: [] }
        },

        organization: {
            Parent: { type: 'ID', refer: 'organization' },
            Name: { type: 'String', required: true },
            Description: { type: 'String' },
            Index: { type: 'Number', required: true },
            IsVirtual: { type: 'Boolean', default: false },
            Profile: { type: 'Object', default: {} },

            Permission: { type: 'Object', default: {} },
        },

        permission: {
            Parent: { type: "ID", refer: 'permission' },
            Name: { type: 'String' },
            Title: { type: 'String' },
            Description: { type: 'String' },
            Path: { type: 'String', unique: true },
            Index: { type: 'Number', required: true },
            Enabled: { type: 'Boolean', required: true, default: true },
            BuiltIn: { type: "Boolean", required: true, default: true },
            Scope: [
                {
                    Name: { type: 'String', required: true },
                    Params: { type: 'Array' },
                }
            ],
        },

        plabel: {
            Name: { type: 'String', required: true, unique: true },
            Description: { type: 'String' },
            Index: { type: 'Number', required: true },
            Enabled: { type: 'Boolean', default: true },
            Permission: { type: 'Object', default: {} },

            // label could be nagtive, means a user with it will DO NOT has it's permissions
            Negative: { type: 'Boolean', default: false },
        },
    },
    utils: {
        verify_api_permission,
        ...require('./utils')
    },
    hasPermission: async (req, mdl) => {
        // compare user permissions, completed permissions, and this api path
        // all the other APIs
        let access_token = req.cookies.token || req.header('Authorization');
        let cacheData = (await req.app.cache.get(access_token)) || {};

        let id = cacheData.userId;
        let user;

        // 用来做第三方集成身份认证的字段
        let userid = req.body.UserId || req.header('UserId');
        let appid = req.body.AppId || req.header('AppId');
        let ts = req.body.Timestamp || req.header('Timestamp');
        // md5(JSON.stringify({Timestamp:xxx, UserId: xxx, UserSecret:xxx }))
        let sign = req.body.Sign || req.header('Sign');

        if (cacheData.type === 'wx') {
            // login with wechat
            user = await req.app.models['account'].findOne({ id, Enabled: true, Deleted: false });
        } else if (cacheData.type === 'pwd') {
            // login with username/email/phone and password
            user = await req.app.models['account'].findOne({ id, Enabled: true, Deleted: false });
        } else if (userid && appid && sign && ts) {
            // 第三方系统集成
            const tmpUser = await req.app.models['account'].findOne({ id: userid, Enabled: true, Deleted: false });

            if (!tmpUser) {
                return false;
            }

            const tmpSign = crypto.MD5(JSON.stringify({
                Timestamp: ts,
                UserId: userid,
                UserSecret: tmpUser.Secret
            }));

            if (tmpSign !== sign) {
                req.app.logger.debug('user: ' + userid + ',sign: ' + sign + ',ts:' + ts + ',realSign: ' + tmpSign);
                return false;
            }

            // 检查请求时间
            if (tmpUser.LastCallTimestamp && tmpUser.LastCallTimestamp >= ts) {
                // 上次请求时间大于当前时间戳
                return false;
            }

            // 身份验证通过
            tmpUser.isIntegration = true;
            user = tmpUser;

            // 更新时间戳
            tmpUser.LastCallTimestamp = ts;
            await tmpUser.save();
        }
        else {
            return false;
        }

        if (!user) {
            return false;
        }

        await req.app.cache.put(access_token, { userId: id, type: cacheData.type }, req.app.config['cacheTimeout']);
        // cache.put(access_token, { userId: id, type: cacheData.type }, req.app.config['cacheTimeout']);
        req.user = user;

        // check user white list, urls in which will be public for all the login users
        const whiteList = ((mdl.config && mdl.config['userWhiteList']) || []);
        for (let i = 0; i < whiteList.length; i += 1) {
            const wl = whiteList[i];

            if (typeof wl === 'string' && wl.toLowerCase() === req.originalUrl.toLowerCase()) return true;

            if (typeof wl === 'object' && new RegExp(wl).test(req.originalUrl)) return true;
        }

        // clear sub account permission for all sub accounts
        // TODO: could we support sub accounts or a sub account??
        if(!mdl.config.subAccountsHaveSubAccountsPermission && req.user && req.user.Parent && req.user.Permission && req.user.Permission.uc && req.user.Permission.uc.sub){
            delete req.user.Permission.uc.sub;
        }

        // if has permission to access the API, then call next
        const hasPerm = await mdl.utils.verify_api_permission(req.app, mdl, user, req.originalUrl);
        if (!!req.originalUrl && hasPerm)
            return true;

        // otherwise return error
        return false;
    },
    i18n: {
        'en-us': {
            'module-title': 'Account',
            'module-description': 'Manage all the accounts and related features in the system.',

            'module-mgmt-title': 'Account management',
            'module-mgmt-description': 'Manage all the accounts in the system.',

            'module-org-title': 'Organization management',
            'module-org-description': 'Manage all the organizations in the system.',
            'module-org-export-title': 'Export Organization',
            'module-org-export-description': 'Export all the organizations from the system.',


            'module-perm-title': 'Permission management',
            'module-perm-description': 'Manage all the permission definitions in the system.',
            'scope-field-label': 'Data Scope',
            'scope-params-header-label': 'Data Scope',
            'scope-params-label': 'Params',

            'Org Based Data Scope': 'Organization based data scope',
            'Data scope base on the organization':'Data scope base on the organization',
            'Self':'Self',
            'My Org': 'The organization',
            'All': 'All',
            'Account Field':'Account field',
            'Org Field':'Organization field',

            'module-label-title': 'Permission Label management',
            'module-label-description': 'Manage all the permission labels in the system.',

            'module-uc-title': 'User Center',
            'module-uc-description': '',
            'module-uc-sub-title': 'Sub Account',
            'module-uc-sub-description': '',
        },
        'zh-cn': {
            'module-title': '账号管理',
            'module-description': '统一管理系统中的账号以及相关功能。',

            'module-mgmt-title': '管理',
            'module-mgmt-description': '统一管理系统中的账号。',

            'module-org-title': '组织机构管理',
            'module-org-description': '统一管理系统中的组织机构。',
            'module-org-export-title': '导出机构',
            'module-org-export-description': '导出系统中所有的机构配置数据。',

            'module-perm-title': '权限定义管理',
            'module-perm-description': '统一管理系统中的权限定义。',
            'scope-field-label': '数据权限',
            'scope-params-header-label': '数据权限',
            'scope-params-label': '关联参数',

            'Org Based Data Scope': '基于组织的数据权限',
            'Data scope base on the organization':'基于组织机构的数据权限控制。',
            'Self':'自己',
            'My Org': '所在机构',
            'All': '全部',
            'Account Field':'代表账号的字段名',
            'Org Field':'代表组织的字段名',

            'module-label-title': '权限标签管理',
            'module-label-description': '统一管理系统中的权限标签。',

            'module-uc-title': '用户中心',
            'module-uc-description': '',
            'module-uc-sub-title': '子账号管理',
            'module-uc-sub-description': '',
        }
    },
    /**
     * Clear cached user permissions, should be called when permission for an user changed all 
     * permissions for all the users changed.
     * 
     * @param {Object} app The app instance
     * @param {String} p The pattern for cache keys, can be an user id. Default is '*' means all.
     */
    clearCachedPermission: (app, p = '*') => {
        // clear all cached permission control (user permissions)
        Promise.resolve(app.cache.keys(`perm_ctrl_${p}`)).then(ks => {
            ks.forEach(k => app.cache.del(k))
        });
    },
    clear_cache_token_by_user_id,
    generate_new_access_token_pwd,
    hooks: {
        onBegin: (app) => {
            app.use(passport.initialize());
        },
        onModulesReady: (app, mdl) => {
            // register the data scope containers
            app.registerContainer(null, 'DataScope', 'The data scope container which will contains all the data scope definitions.', (c, o) => {
                if (!o.Options || !o.Func) {
                    app.logger.error(`Data scope ${o.name} should have options and func!!`)
                }

                return true;
            });

            // add org based data scope 
            // TODO: should be merged to the dataScopes config?
            app.addDataScope({
                mdl: mdl,
                Name: 'orgDataScope',
                Label: mdl.t('Org Based Data Scope'),
                Description: mdl.t('Data scope base on the organization'),
                Options: [
                    {
                        Label: mdl.t('Self'),
                        Value: 'self',
                    },
                    {
                        Label: mdl.t('My Org'),
                        Value: 'org',
                    },
                    {
                        Label: mdl.t('All'),
                        Value: 'all',
                    }
                ],
                Default: 'self',
                Params: [
                    {
                        Label: mdl.t('Account Field'),
                        Name: 'Account',
                        Type: 'String'
                    },
                    {
                        Label: mdl.t('Org Field'),
                        Name: 'Org',
                        Type: 'String',
                    }
                ],
                /**
                 * The function to generate the filter object base on the specified data scope
                 */
                Func: (scope, pScope, p) => {
                        return (req, res, next) => {
                        // add filter according to the data scope
                        let val;
                        const filter = {};

                        // get user data scope for the current router
                        if (req.user && req.user.Permission && p) {
                            const pList = p.split('/');
                            let perm = req.user.Permission;
                            let userScope;

                            for (let i = 0; i < pList.length; i += 1) {
                                const pl = pList[i];

                                if (pl) {
                                    if (perm[pl]) {
                                        perm = perm[pl];
                                        if (perm.Scope) {
                                            userScope = perm.Scope;
                                        }
                                    }
                                }
                            }
                            val = userScope ? userScope['orgDataScope'] : undefined;
                        }

                        // make filter
                        if (typeof val !== 'undefined')
                            switch (val.toString()) {
                                case 'self':
                                    if (req.user.Parent && mdl.config.subAccountsHaveSameDateScope){
                                        filter[pScope.Params[0].Account] = {$in: [req.user.id, req.user.Parent]};
                                    } else {
                                        filter[pScope.Params[0].Account] = req.user.id;
                                    }
                                    res.locals.filter = Object.merge({}, res.locals.filter, filter);
                                    break;
                                case 'org':
                                    filter[pScope.Params[0].Org] = req.user.Org;
                                    res.locals.filter = Object.merge({}, res.locals.filter, filter);
                                    break;
                                default:
                                    break;
                            }

                        return next();
                    }
                }
            });
            
            // add data scope from config
            (mdl.config.dataScopes || []).forEach(ds => {
                ds.Options = ds.Options || [];
                ds.Filters = ds.Filters || [];
                ds.Params = ds.Params || [];

                app.addDataScope({
                    OnlyFor: ds.OnlyFor,
                    mdl: mdl,
                    Name: ds.Name,
                    Label: mdl.t(ds.Label),
                    Description: mdl.t(ds.Description),
                    Options: ds.Options.map(dso => {
                        return {
                            Label: mdl.t(dso.Label),
                            Value: dso.Value,
                            Level: dso.Level,
                        };
                    }),
                    Default: ds.Default,
                    Params: ds.Params.map(dsp => {
                        return {
                            Label: mdl.t(dsp.Label),
                            Name: dsp.Name,
                            Type: dsp.Type,
                        };
                    }),
                    /**
                     * The function to generate the filter object base on the specified data scope
                     */
                    Func: (scope, pScope, p) => {
                            return (req, res, next) => {
                            // add filter according to the data scope
                            let val;
    
                            // get user data scope for the current router
                            if (req.user && req.user.Permission && p) {
                                const pList = p.split('/');
                                let perm = req.user.Permission;
                                let userScope;
    
                                for (let i = 0; i < pList.length; i += 1) {
                                    const pl = pList[i];
    
                                    if (pl) {
                                        if (perm[pl]) {
                                            perm = perm[pl];
                                            if (perm.Scope) {
                                                userScope = perm.Scope;
                                            }
                                        }
                                    }
                                }
                                val = userScope ? userScope[ds.Name] : undefined;
                            }
    
                            // make filter
                            if (typeof val !== 'undefined') {
                                const valStr = val.toString();

                                for(let i = 0; i < ds.Options.length; i += 1) {
                                    const dso = ds.Options[i];
                                    if(valStr === dso.Value) {
                                        const dsov = ds.Filters[dso.Value];
                                        
                                        if(typeof dsov === 'object') {
                                            res.locals.filter = Object.merge({}, res.locals.filter, dsov);
                                        } else if (typeof dsov === 'function') {
                                            res.locals.filter = Object.merge({}, res.locals.filter, dsov(req, mdl, pScope, app, scope, p));
                                        }

                                        break;
                                    }
                                }
                            }
    
                            return next();
                        }
                    }
                });
            });

            // register the permission control  containers
            app.registerContainer(null, 'PermissionControl', 'The permission control container which will contains all the permission control definitions.');

            // add permission controls from config
            (mdl.config.permissionControls || []).forEach(pc => {
                app.addPermissionControl(pc);
            });

            app.addPermissionControl(
                /**
                 * Recalculate the user permission according to the user permission labels
                 * 
                 * Positive labels will be merged with the original user permission while negative labels
                 * will be removed (complement) from the User Permission + Positive Labbels.
                 * 
                 * But all the data scope in labbels will not be calculated specially, 
                 * but just merge together with the functional permissions. 
                 * So according to the labels order, the data scopes will be added or merged or removed.
                 * 
                 * @param {Object} user The user instance
                 * @returns Nothing
                 */
                async (user) => {
                    if(!user || !user.Permission || user.Permission === '*') return;

                    if(typeof user.Permission === 'string') {
                        user.Permission = JSON.parse(user.Permission);
                    }

                    // modify user permission according to the permission labels
                    const userLabels = await app.models.plabel.find({Enabled: true, Name: user.Labels || []}, {Name: 1, Permission: 1, Negative: 1}).lean();
                    const labels = {};

                    for(let i = 0; i < userLabels.length; i += 1) {
                        const lb = userLabels[i];

                        labels[lb.Name] = lb;
                    }

                    const positive = [];
                    const negative = [];
                    for(let i = 0; i < user.Labels.length; i += 1) {
                        const lb = labels[user.Labels[i]];

                        if(!lb) continue;

                        if(lb.Negative) {
                            negative.push(lb);
                        } else {
                            positive.push(lb);
                        }
                    }

                    // merge the positive permission
                    const newPermission = Object.merge(...positive.map(pp => pp.Permission), user.Permission);

                    // remove negative permission
                    Object.complement(newPermission, ...negative.map(np => np.Permission));

                    user.Permission = newPermission;
                }
            );
        },
        onLoadRouters: async (app, m) => {
            // define the local strategy
            passport.use(new LocalStrategy(
                function (uname, pwd, done) {
                    if ((pwd === 'wx' || pwd.startsWith('wx:')) && uname.startsWith('wx:')) {
                        // wx login
                        const code = uname.substring(3);
                        const mp = pwd.startsWith('wx:') && pwd.substring(3);
                        wx.code2session(code, mp).then((wxRes) => {
                            let wxResult = wxRes && wxRes.data;

                            if (wxResult && wxResult.openid) {
                                const openidFilter = {};
                                if (mp) {
                                    openidFilter[`Profile.${mp}.WxOpenId`] = wxResult.openid;
                                } else {
                                    openidFilter['Profile.WxOpenId'] = wxResult.openid;
                                }
                                app.models['account'].findOne(
                                    {
                                        // 'Profile.WxOpenId': wxResult.openid,
                                        ...openidFilter,
                                        Enabled: true,
                                        Deleted: false,
                                    }).then((user) => {
                                        if (user) {
                                            user.isWx = true;
                                            done(null, user);
                                        } else {
                                            // create new 
                                            const profile = {};
                                            if (mp) {
                                                profile[mp] = {
                                                    WxOpenId: wxResult.openid,
                                                };
                                            } else {
                                                profile['WxOpenId'] = wxResult.openid;
                                            }
                                            app.models['account'].create({
                                                Enabled: true,
                                                Deleted: false,
                                                Permission: app.config.account.accountDefaultPermissions || {},
                                                Profile: profile,
                                            }).then((nuser) => {
                                                if (nuser) {
                                                    nuser.isWx = true;
                                                    done(null, nuser);
                                                } else {
                                                    done(null, false);
                                                }
                                            }).catch((err) => {
                                                done(err);
                                            });
                                        }
                                    }).catch((err) => {
                                        done(err);
                                    }
                                );
                            }
                        });
                    } else {
                        const username = crypto.encoder.desDecode(uname, m.config.desKey);
                        const password = crypto.encoder.desDecode(pwd, m.config.desKey);
                        app.models['account'].findOne(
                            {
                                $or: [{ PhoneNumber: username }, { UserName: username }],
                                // Password: password,
                                Enabled: true,
                                Deleted: false,
                            }).then(async (user) => {
                                if (!user) { 
                                    // auto create new user
                                    if (m.config.autoCreateNewUser) {
                                        const valid_phone = (d) => {
                                            return /^(0|86|17951)?(13[0-9]|14[0-9]|15[0-9]|16[0-9]|17[0-9]|18[0-9]|19[0-9])[0-9]{8}$/.test(d);
                                        };
                                        const valid_email = (d) => {
                                            // eslint-disable-next-line no-useless-escape
                                            return /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(d);
                                        }

                                        const userPhoneEmail = {};
                                        if (valid_phone(username)) {
                                            userPhoneEmail.PhoneNumber = username;
                                        } else if (valid_email(username)) {
                                            userPhoneEmail['Profile'] = {
                                                Email: username
                                            };
                                        }
                                        
                                        const permission = Object.assign({}, m.config.accountDefaultPermissions);
                                        clearPermission(permission);
                                        const newU = await app.models['account'].create({
                                            Saved: true,
                                            UserName: username,
                                            Password: '',
                                            Status: m.config.accountRequireAudit ? AccountAuditStatus.Auditing : AccountAuditStatus.Passed,
                                            Permission: permission,
                                            
                                            // set phone number or email
                                            ...userPhoneEmail,
                                        });
                                        return done(null, newU);
                                    } else {
                                        return done(null, false); 
                                    }
                                }

                                const pwdVerified = verifyPassword(password, user.Password, m.config.pwdEncryptMethod || 'md5');

                                return Promise.resolve(app.cache.get(username)).then((cachePwd) => {
                                    if (!pwdVerified && cachePwd !== password) {
                                        return done(null, false); 
                                    } else {
                                        return done(null, user);
                                    }
                                }).catch((err) => {
                                    if (pwdVerified) {
                                        return done(null, false); 
                                    }

                                    return done(err);
                                });
                            }).catch((err) => {
                                done(err);
                            }
                        );
                    }
                }
            ));

            // captcha
            app.post(`${app.config['baseUrl'] || ''}/captcha`,
                async (req, res) => {
                    const captcha = (m.config.captcha.math ? svgCaptcha.createMathExpr : svgCaptcha.create)({
                        ...m.config.captcha.options,
                    });
                    const uuid = uuidv1();

                    res.app.cache.put(`captcha_${uuid}`, captcha.text, m.config.captcha.cache || 300000);
                    const matches = captcha.data.match(/d="([^"]*)"/g);

                    res.endWithData({
                        captcha: matches.map((m) => m.replace('d="', '').replace('"', '')),
                        id: uuid,
                    });
                }
            );

            const verifyCaptcha = async (cid, captcha = '') => {
                if (!captcha) return;

                const captchaCache = await app.cache.get(`captcha_${cid}`);
                if (!captchaCache) return;

                if (m.config.captcha.ignoreCase) {
                    return captchaCache.toLowerCase() === captcha.toLowerCase();
                }

                return captchaCache === captcha;
            };

            // login with the specified strategy
            app.post(`${app.config['baseUrl'] || ''}/logedin`,
                async (req, res) => {
                    // permission control
                    if (!await m.hasPermission(req, m)) {
                        await res.endWithErr(200, 401);
                        return;
                    } else {
                        res.endWithData({});
                        return;
                    }
                }
            );

            // permission control
            app.use(async (req, res, next) => {
                // permission control
                if (!await m.hasPermission(req, m)) {
                    const whiteList = ((m.config && m.config['whiteList']) || []).concat([`${app.config['baseUrl'] || ''}/login`]);
                    for (let i = 0; i < whiteList.length; i += 1) {
                        const wl = whiteList[i];

                        if (typeof wl === 'string' && wl.toLowerCase() === req.originalUrl.toLowerCase()) return next();

                        if (typeof wl === 'object' && new RegExp(wl).test(req.originalUrl)) return next();
                    }

                    if (req.user && req.user.id) {
                        await res.endWithErr(400, 401);
                    }
                    else {
                        res.clearCookie('token');
                        await res.endWithErr(401);
                    }

                    return;
                }

                // update token in cookies
                const token = req.cookies.token;
                if (token) {
                    res.cookie('token', token, { maxAge: app.config['cookieTimeout'] });
                }
                
                return next();
            });

            // check for force reset pwd
            app.use(async (req, res, next) => {
                const resetP = m.config && m.config['forceResetPwd'];

                if(resetP) {
                    if (req.user && req.user.id) {
                        const updateAt = req.user.PwdUpdatedAt || req.user.CreatedDate || req.user.LastUpdateDate;
                        const pastP = new Date() - updateAt;

                        if(pastP > (resetP * 24 * 3600 * 1000)) {
                            await res.endWithErr(403, 'RSTPWD');
                        } else {
                            return next();
                        }
                    }
                    else {
                        await res.endWithErr(401);
                    }

                    return;
                }

                return next();
            });

            // login with the specified strategy
            app.post(`${app.config['baseUrl'] || ''}/login`,
                passport.authenticate(m.config['strategy'] || 'local', { session: false }),
                async (req, res, next) => {
                    if (res._headerSent) return;

                    // check captcha
                    if(m.config.captcha.login && !((req.body.password === 'wx' || req.body.password.startsWith('wx:')) && req.body.username.startsWith('wx:'))) {
                        const { captcha, id : cid } = req.body.captcha || {};
                        if (!captcha || !cid) {
                            res.makeError(400, 'Please provide captcha code!', m);
                            return next('route');
                        }

                        if (!await verifyCaptcha(cid, captcha)) {
                            res.makeError(400, 'Captcha code is incorrect!', m);
                            return next('route');
                        }
                    }

                    // set token into cookie
                    let access_token = req.cookies.token || req.header('Authorization');
                    let token;

                    if ((req.user && req.user.UserName && m.config['keepTokenAccounts'].indexOf(req.user.UserName) >= 0) ||
                        (req.user && req.user.PhoneNumber && m.config['keepTokenAccounts'].indexOf(req.user.PhoneNumber) >= 0)) {
                        // keep token
                        const kt = await app.cache.get(`_keep_token_${req.user.id}`);
                        token = await generate_new_access_token_pwd(app, req.user.id, access_token, kt, req.user.isWx);
                        app.cache.set(`_keep_token_${req.user.id}`, token);
                    } else {
                        token = await generate_new_access_token_pwd(app, req.user.id, access_token, null, req.user.isWx);
                    }

                    res.cookie('token', token, { maxAge: app.config['cookieTimeout'] });

                    res.addData({
                        Name: (req.user.Profile && req.user.Profile.Name) || req.user.PhoneNumber || req.user.UserName || '',
                        Avatar: req.user.Profile && req.user.Profile.Avatar ? req.user.Profile.Avatar : '',
                        Status: req.user.Status,
                    }, false);

                    return next();
                }
            );

            app.post(`${app.config['baseUrl'] || ''}/logout`,
                (req, res, next) => {
                    let access_token = req.cookies.token || req.header('Authorization');

                    // call logout of the passport
                    req.logout(() => {});

                    // clear the cached token
                    res.clearCookie('token');

                    // clear cached data when the account is not in the keep token list
                    // app.cache.del(access_token);
                    if (access_token && (req.user && req.user.UserName && m.config['keepTokenAccounts'].indexOf(req.user.UserName) < 0) &&
                        (req.user && req.user.PhoneNumber && m.config['keepTokenAccounts'].indexOf(req.user.PhoneNumber) < 0)) {
                        app.cache.del(access_token);
                    }

                    res.locals.data = {};

                    return next();
                }
            );

            app.post(`${app.config['baseUrl'] || ''}/can_i`,
                async (req, res, next) => {
                    const urls = (req.body.url || '').split(',');
                    let canDo = [];

                    for (let i = 0; i < urls.length; i += 1) {
                        const url = urls[i];

                        if (!url || !req.user || !await res.app.modules.account.utils.verify_api_permission(req.app, m, req.user, url)) {
                            canDo[i] = false;
                        } else {
                            canDo[i] = true;
                        }
                    }

                    if (canDo.length === 1) canDo = canDo[0];

                    res.addData({ can: canDo });

                    return next();
                }
            );

            // send sms
            app.post(`${(app.config['baseUrl'] || '')}/register/sms`, async (req, res, next) => {
                try {
                    if (!req.body.PhoneNumber) {
                        res.makeError(408, 'Please provide phone number!', m);
                        return next('route');
                    }
                    const phone = crypto.encoder.desDecode(req.body.PhoneNumber, m.config.desKey);

                    // check user existance if necessary
                    if (req.body.exists !== 'all') {
                        const existsCount = await res.app.models.account.countDocuments({$or: [
                            { PhoneNumber: phone },
                            { 'Profile.Email': phone },
                        ]});
    
                        if (req.body.exists === true && existsCount <= 0) {
                            res.makeError(409, 'User not exists!', m);
                            return next('route');
                        }
                        if (req.body.exists === false && existsCount > 0) {
                            res.makeError(410, 'User aleady exists!', m);
                            return next('route');
                        }
                    }

                    const result = await m.sms.sendRandom(phone, m.config.smsFormat || undefined, true, req.body.smsTemp || 'register');

                    if (!result) {
                        res.makeError(500, 'Failed to send sms!', m);
                        return next('route');
                    }
                } catch (ex) {
                    res.makeError(502, ex.message || 'Failed to send sms!', m);
                    return next('route');
                }

                res.addData({});
                return next();
            })

            // verfiy the sms code
            app.post(`${(app.config['baseUrl'] || '')}/register/verify`, async (req, res, next) => {
                if (!req.body.PhoneNumber || !req.body.code) {
                    res.makeError(409, 'Please provide phone number and the sms code!', m);
                    return next('route');
                }
                const phone = crypto.encoder.desDecode(req.body.PhoneNumber, m.config.desKey);
                const result = await m.sms.verify(phone, req.body.code);
                // app.logger.debug(cache.exportJson());

                if (!result) {
                    res.makeError(403, 'Code verification failed!', m);
                    return next('route');
                }

                res.addData({});
                return next();
            })

            // verify phone number (duplication) for register
            app.post(`${(app.config['baseUrl'] || '')}/register/verify/phone`, async (req, res, next) => {
                if (!req.body.PhoneNumber) {
                    res.makeError(408, 'Please provide phone number!', m);
                    return next('route');
                }
                const phone = crypto.encoder.desDecode(req.body.PhoneNumber, m.config.desKey);
                const exists = await res.app.models.account.findOne({
                    $or: [{ PhoneNumber: phone }, { UserName: phone }],
                });
                res.addData({ used: !!exists });
                return next();
            })

            // register with username password
            app.post(`${(app.config['baseUrl'] || '')}/register`,
                async (req, res, next) => {
                    if (!req.body.Password || !req.body.PhoneNumber || !req.body.code) {
                        res.makeError(400, 'Please provide phone number, sms code and the password!', m);
                        return next('route');
                    }
                    const phone = crypto.encoder.desDecode(req.body.PhoneNumber, m.config.desKey);
                    const password = crypto.encoder.desDecode(req.body.Password, m.config.desKey);
                    if (password.length < 6) {
                        res.makeError(402, 'Password does not meet the requirement!', m);
                        return next('route');
                    }

                    const result = await m.sms.verify(phone, req.body.code);

                    if (!result) {
                        res.makeError(403, 'Code verification failed!', m);
                        return next('route');
                    }

                    // check captcha
                    if(m.config.captcha.register) {
                        const { captcha, id : cid } = req.body.captcha || {};
                        if (!captcha || !cid) {
                            res.makeError(400, 'Please provide captcha code!', m);
                            return next('route');
                        }

                        if (!await verifyCaptcha(cid, captcha)) {
                            res.makeError(400, 'Captcha code is incorrect!', m);
                            return next('route');
                        }
                    }

                    const existPhone = await res.app.models.account.countDocuments({ PhoneNumber: phone });
                    if (existPhone) {
                        res.makeError(404, 'The phone number was used already!', m);
                        return next('route');
                    }

                    // only create with specified fields
                    res.locals.body = {
                        Saved: true,
                        PhoneNumber: phone,
                        Password: encryptPwd(password, m.config.pwdEncryptMethod || 'md5')
                    }

                    if (!m.config.accountRequireAudit) {
                        res.locals.body.Status = AccountAuditStatus.Passed;
                    } else {
                        res.locals.body.Status = AccountAuditStatus.Auditing;
                    }

                    const defaultPerm = Object.assign({}, m.config.accountDefaultPermissions);
                    clearPermission(defaultPerm);
                    res.locals.body.Permission = defaultPerm;

                    return next();
                },
                app.CreateDocument('account')
            );

            // recover password
            app.post(`${(app.config['baseUrl'] || '')}/recover`,
                async (req, res, next) => {
                    if (!req.body.Password || !req.body.PhoneNumber || !req.body.code) {
                        res.makeError(400, 'Please provide phone number, sms code and the password!', m);
                        return next('route');
                    }
                    // check captcha
                    if(m.config.captcha.recover) {
                        const { captcha, id : cid } = req.body.captcha || {};
                        if (!captcha || !cid) {
                            res.makeError(400, 'Please provide captcha code!', m);
                            return next('route');
                        }

                        if (!await verifyCaptcha(cid, captcha)) {
                            res.makeError(400, 'Captcha code is incorrect!', m);
                            return next('route');
                        }
                    }

                    const phone = crypto.encoder.desDecode(req.body.PhoneNumber, m.config.desKey);
                    const password = crypto.encoder.desDecode(req.body.Password, m.config.desKey);

                    const result = await m.sms.verify(phone, req.body.code);

                    if (!result) {
                        res.makeError(403, 'Code verification failed!', m);
                        return next('route');
                    }

                    // only create with specified fields
                    if (m.config.recoverNoSamePwd && verifyPassword(password, req.user.Password, m.config.pwdEncryptMethod || 'md5')) {
                        res.makeError(406, 'New password cannot be the same as the old one!', m);
                        return next('route');
                    }

                    res.locals.body = {
                        Password: encryptPwd(password, m.config.pwdEncryptMethod || 'md5'),
                    }

                    res.locals.filter = {
                        PhoneNumber: phone
                    }

                    return next();
                },
                app.UpdateDocument('account', false, (req, res) => {
                    res.locals.data = {};
                })
            );

            // get service list base on the current user permission
            app.get(`${app.config['baseUrl'] || ''}/_service_list`,
                async (req, res, next) => {
                    if (!req.user || !req.user.Permission || Object.keys(req.user.Permission).length <= 0) {
                        res.addData({});
                        return next('route');
                    }

                    let filter;
                    if (req.user.Permission !== '*') {
                        const permPathList = getPermissionPathList(req.user.Permission);
                        filter = { Path: { $in: permPathList } };
                    }

                    res.addData(await __getServiceList(res, filter));

                    return next();
                },
            );

            // process configured data scope
            app.use(function _data_scope_middleware_start (req, res, next) {
                return next();
            });
            app.use(function _data_scope_middleware_end (req, res, next) {
                return next();
            });

            const insertDataScopeMW = (p, n, mw) => {
                // get existing flow routers markers
                const firstIndex = app._router.stack.findIndex(r => r.name === '_data_scope_middleware_start');
                let lastIndex = app._router.stack.findIndex(r => r.name === '_data_scope_middleware_end');

                if (firstIndex < 0 || lastIndex < 0) {
                    app.logger.error('Cannot find the data scope marker middleware!!');
                    process.exit(-1);
                }

                // temp store rest middlewares
                let restRouters = app._router.stack.splice(firstIndex + 1);

                if (restRouters.findIndex(r => r.name === n) < 0) {
                    app.logger.debug(`Adding data scope mw: ${n}`)
                    Object.defineProperty(mw, 'name', { value: n });
                    app.use(`${app.config.baseUrl}${p}(/*)?`, mw);
                }

                // restore the rest middlewares
                app._router.stack = app._router.stack.concat(restRouters);
            };

            const dataScopeList = app.getContainerContent('DataScope');
            for (let i = 0; i < dataScopeList.length; i += 1) {
                const ds = dataScopeList[i];

                if (await app.models.permission.countDocuments({ "Scope.Name": ds.Name }) > 0) {
                    const sList = await app.models.permission.find({ "Scope.Name": ds.Name });
                    for (let j = 0; j < sList.length; j += 1) {
                        const service = sList[j];

                        if(ds.OnlyFor && ds.OnlyFor.findIndex(dsof => {
                            return (dsof.startsWith('/') ? dsof : '/dsof').startsWith(service.Path);
                        }) < 0) continue;

                        if (service.Path) {
                            insertDataScopeMW(service.Path, `${service.Path.replace(/\//g, '_')}_${ds.Name}`, ds.Func(ds, service.Scope.find(ss => ss.Name === ds.Name), service.Path));
                        }
                    }
                }

            }
        },
        onRoutersReady: async (app, m) => {
            // create default user if it's an empty db
            if (await m.models['account'].countDocuments({}) <= 0) {
                // let perms = app.ctx.serviceList()
                // if (!clearPermission(perms)) {
                //     perms = {}
                // }
                const perms = '*';

                await m.models.account.create({
                    Saved: true,
                    Enabled: true,
                    Deleted: false,
                    UserName: m.config.defaultAccountName || 'admin',
                    Password: crypto.MD5(m.config.defaultAccountPwd) || 'f6fdffe48c908deb0f4c3bd36c032e72',
                    Permission: perms,
                    Status: AccountAuditStatus.Passed,
                    Profile: {
                        Name: 'SuperAdmin'
                    }
                });
            }

            // clear all cached permission control (user permissions)
            m.clearCachedPermission(app);

            // TODO: remove service list which are in the white list
        }
    }
})