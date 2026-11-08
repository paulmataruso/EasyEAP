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
  /** The tenant turned on wired 802.1X: Mac profiles also set up network ports; Linux gets wired files for IT staff. */
  wired: boolean
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
  if (route === 'helper') return platform === 'linux' ? <LinuxHelperSteps c={c} /> : <WindowsHelperSteps c={c} />

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
          <Sub>Your computer reads them every time it connects, so don’t delete or move them afterwards.</Sub>
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

/** The terminal command that runs the Linux setup script from the Downloads folder. */
export const linuxCommand = (file: string) => `bash ~/Downloads/${file}`

export function LinuxHelperSteps({ c }: { c: GuideCtx }) {
  const file = c.files.helper ?? 'EasyEAP-WiFi-Setup.sh'
  return (
    <HowTo label="Run the setup script">
      <li>
        Open <b>Terminal</b>: press <b>Ctrl+Alt+T</b>.
        <Sub>Or open your list of apps and search for <Path>Terminal</Path>.</Sub>
      </li>
      <li>
        Paste this command, then press <b>Enter</b>:
        <span className="mt-2 block"><Command value={linuxCommand(file)} what="setup command" /></span>
        <Sub>To paste in Terminal, press <b>Ctrl+Shift+V</b>. If your browser saved the file somewhere else, or saved it as <Path>{file.replace(/\.sh$/, ' (1).sh')}</Path> because you downloaded it before, type <b>bash</b> and a space, drag the newest file into the Terminal window, and press <b>Enter</b>.</Sub>
      </li>
      <li>
        When it asks for your password, type the password you use to sign in to this computer and press <b>Enter</b>.
        <Sub>Nothing shows while you type. Adding a network for the whole computer needs administrator rights; if it says you aren’t allowed, ask your IT administrator to run it for you.</Sub>
      </li>
      <li>
        When it says <b>Done</b>, the network is set up, and connected if you’re near it. This page notices, too.
        <Sub>If it says <b>Setup did not finish</b> instead, the message explains why. Tell your IT administrator what it says.</Sub>
      </li>
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
  if (platform === 'linux' && route === 'helper') {
    return (
      <HowTo label="Connect on Linux">
        <li>If you were near <b>{c.ssid}</b>, the script already connected you. Your computer joins it by itself from now on, for everyone who uses it.</li>
        <li>Somewhere else? Choose <b>{c.ssid}</b> in the Wi-Fi menu (top right) when you’re there. You won’t be asked for a password.</li>
        {c.wired && <li>Using a network cable at work? Network ports that ask for 802.1X use the same certificate; the script set those up too.</li>}
      </HowTo>
    )
  }
  if (platform === 'linux') {
    const pw = password ? <Value value={password} what="certificate password" /> : <span className="en-plain">{route === 'package' ? 'The password from your IT administrator' : 'The password you chose'}</span>
    return (
      <div className="space-y-4">
        <HowTo label="Connect on Linux">
          <li>
            Open <b>Settings → Wi-Fi</b>. If <b>{c.ssid}</b> is already listed as saved (from an earlier try), click the gear or arrow next to it and choose <b>Forget</b> first.
            <Sub>Once a network is saved, clicking it reuses the old settings and asks for things that don’t apply, such as a user name and password.</Sub>
          </li>
          <li>Click <b>{c.ssid}</b>. In the window that opens, fill in these settings exactly, then click <b>Connect</b>.</li>
        </HowTo>
        <Settings
          label="Linux Wi-Fi settings"
          rows={[
            ['Security', c.wpa3 ? 'WPA3 Enterprise' : 'WPA & WPA2 Enterprise'],
            ['Authentication', <span className="en-plain"><b>TLS</b> (not the preselected Tunneled TLS or Protected EAP)</span>],
            ['Identity', <Value value={c.identity} what="identity" />],
            ['Domain', <Value value={c.serverName} what="domain" />],
            ['CA certificate', <span className="en-plain">Choose <b>{c.files.ca ?? 'the CA certificate file'}</b></span>],
            ['User certificate', <span className="en-plain">Choose <b>{c.files.p12 ?? 'your certificate file'}</b>. <b>User private key</b> fills itself in.</span>],
            ['User key password', pw],
          ]}
        />
        <ul className="en-bullets">
          <li><b>Paste</b> the password rather than typing it: the window checks the file after every key you press, which makes typing slow.</li>
          <li>Set the password’s storage option (the icon in the password field) to <b>Store the password for all users</b>. Otherwise your computer may ask for your keyring password, or for the key password again, each time it connects.</li>
          <li>If you’re asked for an administrator password, that’s your computer saving the network for all users. Ask your IT administrator if you don’t have one.</li>
          <li>If the same window comes back asking for a <b>Private key password</b>, connecting failed. The password is almost never the problem: check the <b>Domain</b> and <b>CA certificate</b> above, then forget the network and try again.</li>
        </ul>
        {c.wired && <p className="en-small">Using a network cable at work? Network ports that ask for 802.1X need a wired connection with the same certificate. The <b>Linux setup script</b> sets that up for you.</p>}
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
        {c.wired && <li>Using a network cable at work? The profile also sets up network ports that ask for 802.1X, so your Mac signs in with the same certificate when you plug in.</li>}
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

export function Troubleshoot({ c, platform, route, serial }: { c: GuideCtx; platform: Platform; route?: Route; serial: string | null }) {
  return (
    <ul className="en-bullets">
      <li>Make sure you’re near the <b>{c.ssid}</b> network and that this device’s date and time are set automatically. Certificates don’t work when the clock is wrong.</li>
      {platform === 'linux' && route === 'helper' ? (
        <li>Run the setup script again: it repairs the settings and keeps your certificate. <b>{`${linuxCommand(c.files.helper ?? 'EasyEAP-WiFi-Setup.sh')} --remove`}</b> undoes everything it set up.</li>
      ) : (
        <li>
          Forget <b>{c.ssid}</b> in your Wi-Fi settings, then join again.
          {(platform === 'android' || platform === 'linux') && ' Check each setting above, especially the domain and identity.'}
        </li>
      )}
      <li>Never accept a certificate for a server other than <b>{c.serverName}</b>. If you see a different name, stop and tell your IT administrator.</li>
      <li>
        Still not connecting? Contact your IT administrator at {c.tenant}. Tell them your name, the device ({q(c.deviceName)}) and the time you tried
        {serial ? <>, and quote this certificate number: <span className="ee-mono text-[var(--ee-ink)]">{serial}</span></> : null}.
      </li>
    </ul>
  )
}
