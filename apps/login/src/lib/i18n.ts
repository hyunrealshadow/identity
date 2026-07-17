export const supportedLocales = ['en-US', 'zh-CN'] as const

export type Locale = (typeof supportedLocales)[number]

export const defaultLocale: Locale = 'en-US'

const messages = {
  'en-US': {
    homeTitle: 'Identity interaction app',
    homeDescription: 'Login and OAuth authorization pages are opened by the protocol service with an encrypted login_id. They cannot be started from this page.',
    missingLogin: 'The login context is missing. Start authorization again from the application.',
    missingLoginShort: 'The login context is missing.',
    identifierRequired: 'Enter your email or username.',
    noCredential: 'No supported sign-in method is available for this account.',
    chooseAccount: 'Choose an account',
    chooseAccountDescription: 'Choose a signed-in account, or continue with another account.',
    signIn: 'Sign in to your account',
    signInDescription: 'Enter your email or username to continue securely.',
    useAnotherAccount: 'Use another account',
    identifier: 'Email or username',
    next: 'Next',
    backToAccounts: 'Back to account list',
    loginPrivacy: 'Your sign-in information is used only for this authentication.',
    unableToContinue: 'Unable to continue',
    challengeRequired: 'Enter your verification information.',
    otpTitle: 'Enter verification code',
    passwordTitle: 'Enter password',
    otpDescription: 'Enter the one-time code shown in your authenticator or email.',
    passwordDescription: 'After verifying your password, you may need to complete a second step.',
    verificationFailed: 'Verification failed',
    otp: 'One-time code',
    password: 'Password',
    hidePassword: 'Hide password',
    showPassword: 'Show password',
    verify: 'Verify and continue',
    login: 'Sign in',
    switchAccount: 'Switch account',
    encrypted: 'Credentials are sent over an encrypted connection.',
    missingConsent: 'The authorization context is missing. Start authorization again from the application.',
    missingConsentShort: 'The authorization context is missing.',
    consentTitle: 'Authorize access',
    consentDescription: '{client} wants to access your account.',
    consentFallback: 'Review the authorization request before continuing.',
    consentLoadFailed: 'Unable to load authorization request',
    permissions: 'Requested permissions',
    permissionCount: '{count} items',
    required: 'Required',
    deny: 'Deny',
    allow: 'Allow',
    revoke: 'You can revoke this application’s access at any time in account settings.',
    enhancedNavigationError: 'Enhanced navigation is temporarily unavailable. Refresh the page, or submit again with JavaScript disabled.',
    temporaryError: 'The request cannot be completed right now. Try again later.',
    scope_openid: 'Verify your identity.',
    scope_profile: 'View your basic profile information.',
    scope_email: 'View your email address.',
    scope_address: 'View your postal address.',
    scope_phone: 'View your phone number.',
    scope_offline_access: 'Maintain access when you are not using the application.',
  },
  'zh-CN': {
    homeTitle: 'Identity 交互应用',
    homeDescription: '登录和 OAuth 授权页面由协议服务携带加密的 login_id 跳转进入，不能从首页直接开始。',
    missingLogin: '缺少登录上下文，请从应用重新发起授权。',
    missingLoginShort: '缺少登录上下文。',
    identifierRequired: '请输入邮箱或用户名。',
    noCredential: '该账号没有可用的登录方式。',
    chooseAccount: '选择账号',
    chooseAccountDescription: '选择一个已登录账号，或使用其他账号继续。',
    signIn: '登录你的账号',
    signInDescription: '输入邮箱或用户名以继续安全授权流程。',
    useAnotherAccount: '使用其他账号',
    identifier: '邮箱或用户名',
    next: '下一步',
    backToAccounts: '返回账号列表',
    loginPrivacy: '登录信息仅用于完成本次身份验证',
    unableToContinue: '无法继续',
    challengeRequired: '请输入验证信息。',
    otpTitle: '输入验证码',
    passwordTitle: '输入密码',
    otpDescription: '请输入验证器或邮件中显示的一次性验证码。',
    passwordDescription: '验证密码后，你可能还需要完成第二步验证。',
    verificationFailed: '验证失败',
    otp: '一次性验证码',
    password: '密码',
    hidePassword: '隐藏密码',
    showPassword: '显示密码',
    verify: '验证并继续',
    login: '登录',
    switchAccount: '更换账号',
    encrypted: '凭据将通过加密连接发送',
    missingConsent: '缺少授权上下文，请从应用重新发起授权。',
    missingConsentShort: '缺少授权上下文。',
    consentTitle: '授权访问',
    consentDescription: '{client} 希望访问你的账号。',
    consentFallback: '检查授权请求后再继续。',
    consentLoadFailed: '无法加载授权请求',
    permissions: '请求的权限',
    permissionCount: '{count} 项',
    required: '必需',
    deny: '拒绝',
    allow: '允许',
    revoke: '你可以随时在账号设置中撤销此应用的访问权限。',
    enhancedNavigationError: '增强导航暂时不可用。你可以刷新页面，或禁用 JavaScript 后继续提交。',
    temporaryError: '请求暂时无法完成，请稍后重试。',
    scope_openid: '验证你的身份。',
    scope_profile: '查看你的基本个人资料。',
    scope_email: '查看你的邮箱地址。',
    scope_address: '查看你的邮寄地址。',
    scope_phone: '查看你的电话号码。',
    scope_offline_access: '在你未使用应用时保持访问权限。',
  },
} as const

export type MessageKey = keyof (typeof messages)['en-US']

function matchLocale(value: string | undefined): Locale | undefined {
  const normalized = value?.trim().toLowerCase()
  if (!normalized) return undefined
  if (normalized === 'zh' || normalized.startsWith('zh-')) return 'zh-CN'
  if (normalized === 'en' || normalized.startsWith('en-')) return 'en-US'
  return undefined
}

export function resolveLocale(options: {
  uiLocales?: readonly string[]
  acceptLanguage?: string | null
} = {}): Locale {
  for (const candidate of options.uiLocales ?? []) {
    const locale = matchLocale(candidate)
    if (locale) return locale
  }
  for (const part of options.acceptLanguage?.split(',') ?? []) {
    const locale = matchLocale(part.split(';')[0])
    if (locale) return locale
  }
  return defaultLocale
}

export function translate(
  locale: Locale,
  key: MessageKey,
  values: Record<string, string | number> = {},
) {
  return Object.entries(values).reduce(
    (message, [name, value]) => message.replaceAll(`{${name}}`, String(value)),
    messages[locale][key] as string,
  )
}

export function scopeDescription(locale: Locale, name: string, fallback: string) {
  const key = `scope_${name}` as MessageKey
  return key in messages[locale] ? translate(locale, key) : fallback
}
