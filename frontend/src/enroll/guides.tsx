// Plain-language, platform-specific install and connect steps. Every value a person must type comes from the API.
import type { ReactNode } from 'react'
import type { Platform } from './api'
import { Command, Value } from './ui'

/** How the certificate reaches the device. */
export type Route = 'profile' | 'p12' | 'helper' | 'package'

export interface GuideCtx {
  tenant: string
  ssid: string
  serverName: string
  wpa3: boolean
  identity: string
  deviceName: string
  /** Name iOS/macOS shows for the configuration profile (from the API's profile). */
  profileName: string | null
  /** Root CA common name, for the "do you trust this certificate?" prompts. */
  rootCn: string | null
  /** Downloaded file names. `profile`: an Apple configuration profile (made here, or IT's package). */
  files: { p12?: string; profile?: string; ca?: string; xml?: string; helper?: string }
  /** Name the person gives the certificate on Android (we suggest the SSID). */
  androidCertName: string
}

const Path = ({ children }: { children: ReactNode }) => <span className="en-path">{children}</span>
const Sub = ({ children }: { children: ReactNode }) => <span className="en-sub">{children}</span>
const q = (s: string) => `“${s}”`

export function HowTo({ children, label }: { children: ReactNode; label: string }) {
  return <ol className="en-howto" aria-label={label}>{children}</ol>
}

export function Settings({ rows, label }: { rows: Array<[string, ReactNode]>; label: string }) {
  return (
    <dl className="en-settings" aria-label={label}>
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{typeof v === 'string' ? <span className="en-plain">{v}</span> : v}</dd>
        </div>
      ))}
    </dl>
  )
}

const rootName = (c: GuideCtx) => (c.rootCn ? <b>{q(c.rootCn)}</b> : <>your organisation’s root certificate</>)

// ── Install ──────────────────────────────────────────────────────────────
export function InstallSteps({ platform, route, c }: { platform: Platform; route: Route; c: GuideCtx }) {
  if (route === 'helper') return <WindowsHelperSteps c={c} />

  if (platform === 'ios') {
    return (
      <HowTo label="Install on iPhone or iPad">
        <li>
          {route === 'profile'
            ? <>Tap <b>Download the Wi-Fi profile</b> above. When Safari asks, tap <b>Allow</b>, then <b>Close</b>.</>
            : <>When Safari asks about a configuration profile, tap <b>Allow</b>, then <b>Close</b>. If you missed it, tap <b>Save again</b> above.</>}
        </li>
        <li>
          Open the <b>Settings</b> app and tap <b>Profile Downloaded</b>, near the top.
          <Sub>Don’t see it? Go to <Path>General → VPN &amp; Device Management</Path> and tap it there.</Sub>
        </li>
        <li>
          {c.profileName ? <>Check that it’s called <b>{q(c.profileName)}</b>. Then tap </> : <>Tap </>}
          <b>Install</b> and enter your device passcode.
          <Sub>iOS may mark it “Not Verified” because it isn’t digitally signed. Check the name instead.</Sub>
        </li>
        <li>
          Tap <b>Install</b> again. When asked for the certificate’s password, {route === 'package' ? 'enter the password from your IT administrator' : 'paste the password shown above'}, then tap <b>Next</b> and <b>Done</b>.
        </li>
      </HowTo>
    )
  }

  if (platform === 'macos') {
    if (c.files.profile) {
      return (
        <HowTo label="Install on a Mac">
          <li>
            {route === 'package'
              ? <>Open <b>{c.files.profile}</b> from your <b>Downloads</b> folder (double-click it).</>
              : <>Click <b>Download the Wi-Fi profile</b> above, then open the file from your <b>Downloads</b> folder.</>}
            {' '}macOS says the profile is ready for review.
          </li>
          <li>
            Open <b>System Settings</b> and search for <b>Profiles</b>.
            <Sub>macOS 15 and later: <Path>General → Device Management</Path>. Earlier versions: <Path>Privacy &amp; Security → Profiles</Path>.</Sub>
          </li>
          <li>
            Double-click {c.profileName ? <b>{q(c.profileName)}</b> : 'the Wi-Fi profile'} and click <b>Install</b>.
            <Sub>macOS may say the profile is unsigned or not verified. Check the name instead.</Sub>
          </li>
          <li>Enter {route === 'package' ? 'the password from your IT administrator' : 'the certificate’s password shown above'} when asked for the certificate’s password, then your Mac’s login password.</li>
        </HowTo>
      )
    }
    return (
      <HowTo label="Install on a Mac">
        <li>Open <b>{c.files.p12 ?? 'the certificate file'}</b> from your <b>Downloads</b> folder (double-click it). <b>Keychain Access</b> opens.</li>
        <li>Choose the <b>login</b> keychain if asked, and click <b>Add</b>.</li>
        <li>Enter {route === 'package' ? 'the password from your IT administrator' : 'the certificate’s password shown above'}, then click <b>OK</b>.</li>
      </HowTo>
    )
  }

  if (platform === 'android') {
    return (
      <HowTo label="Install on Android">
        <li>{route === 'package' ? <>Your certificate is in <b>Downloads</b> as <b>{c.files.p12}</b>.</> : <>Tap <b>Download the certificate</b> above. It’s saved to <b>Downloads</b> as <b>{c.files.p12}</b>.</>}</li>
        <li>
          Open <b>Settings</b>, search for <b>Wi-Fi certificate</b> and tap it.
          <Sub>On many phones it’s under <Path>Security &amp; privacy → More security settings → Encryption &amp; credentials → Install a certificate → Wi-Fi certificate</Path>.</Sub>
        </li>
        <li>Choose <b>{c.files.p12}</b> and enter {route === 'package' ? 'the password from your IT administrator' : 'the password shown above'}.</li>
        <li>
          When asked to name the certificate, type <b>{c.androidCertName}</b> and tap <b>OK</b>.
          <Sub>You’ll pick this name when you join the network.</Sub>
        </li>
      </HowTo>
    )
  }

  if (platform === 'linux') {
    return (
      <HowTo label="Install on Linux">
        <li>Download {route === 'package' ? 'the files' : 'both files'} above.</li>
        <li>
          Move them to a folder you’ll keep, for example a folder called <b>wifi</b> in your home folder.
          <Sub>Your computer reads them every time it connects, so don’t delete them.</Sub>
        </li>
      </HowTo>
    )
  }

  // Windows, certificate file (browser fallback or IT's package)
  return (
    <HowTo label="Install on Windows">
      <li>
        Double-click <b>{c.files.p12 ?? 'the certificate file'}</b> in your <b>Downloads</b> folder. In the <b>Certificate Import Wizard</b>, choose <b>Current User</b> and click <b>Next</b>, then <b>Next</b> again.
      </li>
      <li>Enter {route === 'package' ? 'the password from your IT administrator' : 'the password shown above'} and click <b>Next</b>. Keep <b>Automatically select the certificate store</b>, click <b>Next</b>, then <b>Finish</b>.</li>
      <li>If Windows warns that you’re about to install a certificate from {rootName(c)}, check the name and click <b>Yes</b>.</li>
      {c.files.xml && (
        <li>
          Add the Wi-Fi network: open <b>PowerShell</b> (press Start, type <b>PowerShell</b>, press Enter) and paste this command, then press Enter:
          <span className="mt-2 block">
            <Command value={`netsh wlan add profile filename="$env:USERPROFILE\\Downloads\\${c.files.xml}" user=current`} what="network setup command" />
          </span>
          <Sub>If your browser saved the file somewhere else or renamed it, change the path to match.</Sub>
        </li>
      )}
    </HowTo>
  )
}

export function WindowsHelperSteps({ c }: { c: GuideCtx }) {
  return (
    <HowTo label="Run the setup helper">
      <li>Open your <b>Downloads</b> folder.</li>
      <li>
        Right-click <b>{c.files.helper ?? 'EasyEAP-WiFi-Setup.ps1'}</b> and choose <b>Run with PowerShell</b>.
        <Sub>On Windows 11, choose <Path>Show more options</Path> first.</Sub>
      </li>
      <li>
        If PowerShell asks whether to change the execution policy, type <b>Y</b> and press <b>Enter</b>.
        <Sub>This applies only to that one window.</Sub>
      </li>
      <li>When Windows asks whether to install a certificate from {rootName(c)}, check the name and click <b>Yes</b>.</li>
      <li>
        When it says <b>Done</b>, press <b>Enter</b> to close the window. This page notices, too.
        <Sub>If it says <b>Setup did not finish</b> instead, the message after it explains why. Tell your IT administrator what it says.</Sub>
      </li>
    </HowTo>
  )
}

// ── Connect ──────────────────────────────────────────────────────────────
export function ConnectSteps({ platform, route, c, password }: { platform: Platform; route: Route; c: GuideCtx; password: string | null }) {
  const trust = (
    <>If you’re asked to trust a certificate, check that it’s for <b>{c.serverName}</b>. If it shows any other name, don’t accept it.</>
  )
  if (platform === 'android') {
    return (
      <div className="space-y-4">
        <HowTo label="Connect on Android">
          <li>Open <b>Settings → Wi-Fi</b> and tap <b>{c.ssid}</b>.</li>
          <li>Fill in these settings exactly, then tap <b>Connect</b>.</li>
        </HowTo>
        <Settings
          label="Android Wi-Fi settings"
          rows={[
            ['EAP method', 'TLS'],
            ['CA certificate', <span className="en-plain"><b>{c.androidCertName}</b> (the name you chose)</span>],
            ['Domain', <Value value={c.serverName} what="domain" />],
            ['User certificate', <span className="en-plain"><b>{c.androidCertName}</b></span>],
            ['Identity', <Value value={c.identity} what="identity" />],
            ['Anonymous identity', 'Leave blank'],
          ]}
        />
        <p className="en-small">If <b>CA certificate</b> doesn’t list {q(c.androidCertName)}, install the CA certificate file from the previous step the same way, as a Wi-Fi certificate.</p>
      </div>
    )
  }
  if (platform === 'linux') {
    return (
      <div className="space-y-4">
        <HowTo label="Connect on Linux">
          <li>Open <b>Settings → Wi-Fi</b> (or your network menu) and choose <b>{c.ssid}</b>.</li>
          <li>Fill in these settings, then click <b>Connect</b>.</li>
        </HowTo>
        <Settings
          label="Linux Wi-Fi settings"
          rows={[
            ['Security', c.wpa3 ? 'WPA3 Enterprise' : 'WPA & WPA2 Enterprise'],
            ['Authentication', 'TLS'],
            ['Identity', <Value value={c.identity} what="identity" />],
            ['Domain', <Value value={c.serverName} what="domain" />],
            ['CA certificate', <span className="en-plain">Choose <b>{c.files.ca ?? 'the CA certificate file'}</b></span>],
            ['User certificate', <span className="en-plain">Choose <b>{c.files.p12 ?? 'your certificate file'}</b></span>],
            ['User key password', password ? <Value value={password} what="certificate password" /> : <span className="en-plain">{route === 'package' ? 'The password from your IT administrator' : 'The password you chose'}</span>],
          ]}
        />
        <p className="en-small">Some versions call it <b>User certificate password</b>. When you choose the certificate file, the private key field fills itself in.</p>
      </div>
    )
  }
  if (route === 'package' && !c.files.profile && (platform === 'ios' || platform === 'macos')) {
    return (
      <div className="space-y-4">
        <HowTo label={`Connect on ${platform === 'ios' ? 'iPhone or iPad' : 'Mac'}`}>
          <li>{platform === 'ios' ? <>Open <b>Settings → Wi-Fi</b> and tap <b>{c.ssid}</b>.</> : <>Click the <b>Wi-Fi</b> icon in the menu bar and choose <b>{c.ssid}</b>.</>}</li>
          <li>Set <b>Mode</b> to <b>EAP-TLS</b> and choose your certificate under <b>Identity</b>. If asked for a username, enter the identity below. Then {platform === 'ios' ? 'tap' : 'click'} <b>Join</b>.</li>
          <li>When asked to trust the server’s certificate, check that it’s for <b>{c.serverName}</b>, then {platform === 'ios' ? 'tap' : 'click'} <b>Trust</b>. If it shows any other name, cancel.</li>
        </HowTo>
        <Settings label="Wi-Fi settings" rows={[['Identity', <Value value={c.identity} what="identity" />], ['Server name', <Value value={c.serverName} what="server name" copy={false} />]]} />
      </div>
    )
  }
  if (platform === 'ios') {
    return (
      <HowTo label="Connect on iPhone or iPad">
        <li>Your iPhone or iPad joins <b>{c.ssid}</b> by itself when it’s in range.</li>
        <li>If it doesn’t, open <b>Settings → Wi-Fi</b> and tap <b>{c.ssid}</b>. {trust}</li>
      </HowTo>
    )
  }
  if (platform === 'macos') {
    return (
      <HowTo label="Connect on a Mac">
        <li>Click the <b>Wi-Fi</b> icon in the menu bar and choose <b>{c.ssid}</b>.</li>
        <li>If you’re asked which certificate to use, choose the one for <b>{c.identity}</b>. {trust}</li>
      </HowTo>
    )
  }
  // Windows
  if (route === 'helper' || c.files.xml) {
    return (
      <HowTo label="Connect on Windows">
        <li>Select the <b>Wi-Fi</b> icon at the right of the taskbar.</li>
        <li>Choose <b>{c.ssid}</b> and select <b>Connect</b>. You won’t be asked for a password.</li>
      </HowTo>
    )
  }
  return (
    <HowTo label="Connect on Windows">
      <li>Select the <b>Wi-Fi</b> icon at the right of the taskbar, choose <b>{c.ssid}</b> and select <b>Connect</b>.</li>
      <li>Instead of a user name and password, choose <b>Connect using a certificate</b> and pick the certificate for <b>{c.identity}</b>.</li>
      <li>Windows asks whether to continue connecting. Select <b>Show certificate details</b>, check the server is <b>{c.serverName}</b>, then select <b>Connect</b>. If it shows any other name, cancel.</li>
    </HowTo>
  )
}

export function Troubleshoot({ c, platform, serial }: { c: GuideCtx; platform: Platform; serial: string | null }) {
  return (
    <ul className="en-bullets">
      <li>Make sure you’re near the <b>{c.ssid}</b> network and that this device’s date and time are set automatically. Certificates don’t work when the clock is wrong.</li>
      <li>
        Forget <b>{c.ssid}</b> in your Wi-Fi settings, then join again.
        {(platform === 'android' || platform === 'linux') && ' Check each setting above, especially the domain and identity.'}
      </li>
      <li>Never accept a certificate for a server other than <b>{c.serverName}</b>. If you see a different name, stop and tell your IT administrator.</li>
      <li>
        Still not connecting? Contact your IT administrator at {c.tenant}. Tell them your name, the device ({q(c.deviceName)}) and the time you tried
        {serial ? <>, and quote this certificate number: <span className="ee-mono text-[var(--ee-ink)]">{serial}</span></> : null}.
      </li>
    </ul>
  )
}
