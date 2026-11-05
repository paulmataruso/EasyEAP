// What device and browser is this? Used to pick the deliverable and to warn before anything irreversible happens.
import type { Platform } from './api'

export const platformName: Record<Platform, string> = {
  ios: 'iPhone or iPad',
  macos: 'Mac',
  android: 'Android phone or tablet',
  windows: 'Windows computer',
  linux: 'Linux computer',
}
/** With its article, for sentences: "this looks like a Mac". */
export const platformA: Record<Platform, string> = {
  ios: 'an iPhone or iPad',
  macos: 'a Mac',
  android: 'an Android phone or tablet',
  windows: 'a Windows computer',
  linux: 'a Linux computer',
}
export const platformShort: Record<Platform, string> = { ios: 'iPhone or iPad', macos: 'Mac', android: 'Android', windows: 'Windows', linux: 'Linux' }

export interface Environment {
  /** Best guess at the platform, or null when it can't be told (e.g. ChromeOS). */
  detected: Platform | null
  /** An app's built-in browser (Facebook, Instagram, LinkedIn, Gmail's Google app, an Android WebView…). */
  inAppBrowser: boolean
  /** iOS/iPadOS browser other than Safari (profiles install only from Safari). */
  iosNotSafari: boolean
  /** Name for the in-app browser message, when known. */
  appName: string | null
}

const APPS: Array<[RegExp, string]> = [
  [/FBAN|FBAV|FB_IAB|FBIOS/i, 'Facebook'],
  [/Instagram/i, 'Instagram'],
  [/LinkedInApp/i, 'LinkedIn'],
  [/Twitter|TwitterAndroid/i, 'X'],
  [/MicroMessenger/i, 'WeChat'],
  [/\bLine\//i, 'LINE'],
  [/Snapchat/i, 'Snapchat'],
  [/TikTok|BytedanceWebview|musical_ly/i, 'TikTok'],
  [/WhatsApp/i, 'WhatsApp'],
  [/Teams\//i, 'Teams'],
  [/Slack/i, 'Slack'],
  [/\bGSA\//i, 'the Google app'],
]

export function detectEnvironment(nav: Navigator = navigator): Environment {
  const ua = nav.userAgent || ''
  const touch = (nav.maxTouchPoints ?? 0) > 1
  let detected: Platform | null = null
  if (/iPhone|iPod|iPad/i.test(ua)) detected = 'ios'
  else if (/Macintosh|Mac OS X/i.test(ua)) detected = touch ? 'ios' : 'macos' // iPadOS 13+ reports itself as a Mac
  else if (/Android/i.test(ua)) detected = 'android'
  else if (/Windows/i.test(ua)) detected = 'windows'
  else if (/CrOS/i.test(ua)) detected = null
  else if (/Linux|X11/i.test(ua)) detected = 'linux'

  const app = APPS.find(([re]) => re.test(ua))
  const androidWebView = detected === 'android' && /; wv\)/.test(ua)
  // iOS WebKit views inside apps have "Mobile/" but no "Safari/" token.
  const iosWebView = detected === 'ios' && /AppleWebKit/i.test(ua) && !/Safari\//i.test(ua)
  const iosOtherBrowser = detected === 'ios' && /CriOS|FxiOS|EdgiOS|OPiOS|OPT\/|YaBrowser|DuckDuckGo|Brave/i.test(ua)
  const inAppBrowser = !!app || androidWebView || iosWebView
  return { detected, inAppBrowser, iosNotSafari: detected === 'ios' && (inAppBrowser || iosOtherBrowser), appName: app ? app[1] : null }
}
