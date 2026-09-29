const labs = [
  { id: 'idor', number: '01', category: 'ACCESS CONTROL', title: 'Insecure Direct Object Reference', short: 'IDOR', description: 'A profile page trusts the number in its URL. Change it and see whose fictional account the app returns.', tag: 'OBJECT AUTHORIZATION', note: 'A hard-to-guess ID is not access control. The server must verify who is allowed to read each object.', hints: ['Compare your own profile URL ending in /1001 with the ID in the request. What happens if the same page asks for another existing profile?', 'The lab has a second synthetic profile at 1002. Change only the number at the end of the practice URL, then press Go.'], steps: [
    ['What it is', 'An insecure direct object reference (IDOR) is an authorization failure: a request names a record by an ID, but the server does not check whether the current user may access that record.'],
    ['How to find it', 'Change the profile URL from /profile/1001 to /profile/1002 and compare the response. In an application review, inspect routes and API handlers that accept record IDs, then verify each request checks the signed-in user against the requested record.'],
    ['What makes it vulnerable', 'The handler looks up profiles.get(user_id) using the client-supplied ID and returns the result without checking ownership. The flaw is introduced when the record lookup itself is treated as permission to access the record.'],
    ['How to solve it', 'Require authentication and enforce object-level authorization on every read and write. Scope the lookup to both the requested record ID and the current user\'s owner ID; deny access when they do not match. Hidden links and unguessable IDs are not authorization.'],
    ['Impact', 'An attacker may read or change another user\'s private data, depending on the endpoint. This can expose personal information, account details, or confidential business records.']
  ], solution: [
    'Open Practice and find the profile URL ending in /profile/1001.',
    'Change only the ID to 1002 and press Go.',
    'Confirm the page now shows Riley Park and the synthetic private note. The objective should mark complete.'
  ]},
  { id: 'xss', number: '02', category: 'INJECTION', title: 'Cross-Site Scripting', short: 'XSS', description: 'A greeting reflects input as HTML. Make the browser execute a harmless proof inside the isolated frame.', tag: 'OUTPUT ENCODING', note: 'Treat user input as text. Context-aware output encoding or safe DOM APIs keep markup from becoming executable code.', hints: ['Your message is returned inside a heading. If the app treats input as HTML instead of text, the browser may interpret tags rather than display them.', 'For a harmless proof, enter a script that calls parent.postMessage({type:\'vulnlab-xss-proof\',marker:\'sandbox-script-ran\'},\'*\'). It only reports completion to the lab page; the sandbox blocks network access and parent DOM access.'], steps: [
    ['What it is', 'Cross-site scripting (XSS) occurs when untrusted input is inserted into a web page as executable HTML or script. The browser interprets it in the context of the page that served it.'],
    ['How to find it', 'Trace a value you control from the request into the response and inspect where it is rendered. Here, submit a greeting and observe that the endpoint returns HTML containing it. In real reviews, inspect templates, DOM sinks, and uses of innerHTML or document.write with untrusted values.'],
    ['What makes it vulnerable', 'The endpoint builds a heading with an f-string containing the raw name. The vulnerability is introduced by inserting that value into HTML without escaping it for the HTML text context. This lab confines execution to an opaque-origin sandbox with network access blocked.'],
    ['How to solve it', 'Prefer template rendering with auto-escaping or encode the value for its exact output context. In client-side code, use textContent instead of innerHTML for plain text. Content Security Policy is defense in depth, not a replacement for safe output handling.'],
    ['Impact', 'Depending on the page, injected script can impersonate the user, read page data available to the script, alter content, or perform actions with the user\'s authority. The local lab sandbox deliberately prevents these real-world effects.']
  ], solution: [
    'Open Practice and enter a harmless greeting in the message field.',
    "Enter <script>alert('XSS')</script> and select Open My Workspace.",
    'The proof runs only inside the opaque-origin sandbox and reports completion to the lab page. No network access or parent-page DOM access is granted.'
  ]},
  { id: 'sqli', number: '03', category: 'INJECTION', title: 'SQL Injection', short: 'SQLi', description: 'A sign-in lookup stitches text into SQL. Change the query logic to reveal only the fake lab accounts.', tag: 'PARAMETERIZED QUERIES', note: 'Bind values as parameters instead of concatenating them into SQL. Validation alone does not prevent SQL injection.', hints: ['The username and PIN are placed inside a SQL WHERE condition. Think about how a quote could end a string and change that condition.', 'A tautology such as 1=1 is always true. A SQL comment can make the rest of this toy query irrelevant. Only fake rows are available.'], steps: [
    ['What it is', 'SQL injection happens when untrusted input is interpreted as part of a database command instead of as a value. Input can then change the logic of the query.'],
    ['How to find it', 'Trace request fields into database calls. In this lab, compare a normal search with the query construction in the search handler. In code review, look for SQL assembled with string formatting, concatenation, or interpolation.'],
    ['What makes it vulnerable', 'The handler inserts username and PIN directly into a SQL f-string. A quote in either value can end the intended string literal and let the remaining input alter the WHERE condition. The query here runs only against synthetic in-memory accounts.'],
    ['How to solve it', 'Use a prepared statement and pass values separately, for example database.execute("SELECT ... WHERE username = ? AND pin = ?", (username, pin)). The database then treats inputs as data, not SQL syntax. Validation does not replace parameter binding.'],
    ['Impact', 'The data exposed or changed depends on database permissions and reachable queries. Consequences can include bypassing checks, reading or modifying records, or damaging data.']
  ], solution: [
    'Open Practice and locate the username and PIN fields.',
    'In the username field, enter \' OR \'1\'=\'1\' -- and put x in the PIN field, then select Search Directory.',
    'Confirm that the response contains the three synthetic training accounts and that the objective is complete. This lab uses only its temporary in-memory database.'
  ]},
  { id: 'auth', number: '04', category: 'AUTHENTICATION', title: 'Broken Authentication', short: 'BROKEN AUTH', description: 'The training reset flow issues predictable, non-expiring tokens. Use one to take over the synthetic admin account.', tag: 'SECURE RESET FLOWS', note: 'Reset tokens should be cryptographically random, single-use, short-lived, and bound to the account and request.', hints: [
    'The reset request intentionally returns a generic message, not the token. Since this is a local source-code lab, inspect reset_password() in app.py and find what value the submitted token is compared against.',
    'The check compares against reset- followed by the username. Substitute the synthetic account name admin to derive reset-admin. Use this token only in the local lab.'
  ], steps: [
    ['What it is', 'Authentication verifies that someone is who they claim to be. Broken authentication includes weaknesses in sign-in and account recovery. A reset token acts like a temporary password, so anyone who can predict it may take over the account.'],
    ['How to find it', 'The reset form does not show the token; its generic response is intentional. In this source-code lab, open app.py and inspect reset_password(). The condition compares the submitted token with f\'reset-{username}\'. Replacing username with the training account admin gives reset-admin. You can also reveal this in Practice with Need a hint?'],
    ['What makes it vulnerable', 'The server derives the token from the public username instead of using a secret random value. The same token remains accepted because the code does not expire it or mark it as used. A generic reset message helps prevent account discovery, but it cannot make a predictable token safe.'],
    ['How to solve it', 'Generate a long, unpredictable token with a cryptographically secure random generator, store it safely and bind it to one account, then expire it quickly and invalidate it after one use. Rate-limit reset attempts, keep responses generic and similar in timing, notify the account owner, and require the user to sign in normally after resetting.'],
    ['Impact', 'Someone who predicts or obtains a valid reset token may replace the victim\'s password and take over the account. Account takeover can expose private data and allow actions available to that account.']
  ], solution: [
    'Open Practice. Keep the account set to the synthetic admin account.',
    'In this code lab, app.py shows the check reset-{username}. For the synthetic admin account, replace {username} with admin to get reset-admin. Enter it with a practice-only password, then select Set New Password.',
    'Sign in as admin with the new password. The lab objective completes when the local training flag appears.'
  ]},
  { id: 'cmdi', number: '05', category: 'INJECTION', title: 'Command Injection', short: 'CMDI', description: 'A member lookup combines your input with a simulated command. See how a separator can add more training actions.', tag: 'SAFE COMMAND EXECUTION', note: 'Avoid shells for user input. Prefer direct APIs or fixed executables with argument arrays and shell=False.', hints: [
    'Start with the normal lookup value mira. The training console models an application that appends your input to a command string.',
    'A semicolon separates shell commands. In this safe simulator, try mira; ls to see the fake files, then mira; cat show-training-note to read the secret note.'
  ], steps: [
    ['What it is', 'Command injection happens when an application puts untrusted input into an operating-system command and a shell interprets that input as command syntax. A separator can turn one intended command into multiple commands.'],
    ['How to find it', 'Trace user input into process-launching code and look for shell command strings, shell=True, or string concatenation. In this lab, run a normal lookup, then compare it with a value containing a semicolon. The console is a bounded simulator, not an operating-system shell.'],
    ['What makes it vulnerable', 'The unsafe real-world pattern is building a command string with untrusted input and asking a shell to interpret it. This lab models that boundary: the semicolon splits the simulated lookup from extra actions like ls and cat. The simulator only recognizes fixed training actions and never launches a process.'],
    ['How to solve it', 'Best: replace shell commands with a direct library or API. If a process is essential, use a fixed executable and an argument list with shell=False; never concatenate user input into a shell string. Validate values against a strict allowlist and run the service with least privilege.'],
    ['Impact', 'A real injected command runs with the application process\'s permissions. Depending on those permissions, it could expose or alter files, access secrets, or disrupt the service. This lab can reveal only its fictional training note.']
  ], solution: [
    'Open Practice and run a normal lookup with mira.',
    'Change the value to mira; ls to list the fake files and confirm show-training-note appears.',
    'Then try mira; cat show-training-note to read the synthetic note and finish the objective.'
  ]}
];

const storageKey = 'vulnlab-progress-v1';
let progress = readProgress();
let activeLab = null;
let activeMode = 'walkthrough';
let xssProofReceived = false;
let hintIndex = 0;
let noticeKind = '';

function readProgress() {
  try {
    const stored = JSON.parse(localStorage.getItem(storageKey) || '{}');
    return Object.fromEntries(labs.map(lab => [lab.id, Boolean(stored[lab.id])]));
  } catch { return Object.fromEntries(labs.map(lab => [lab.id, false])); }
}
function saveProgress() { localStorage.setItem(storageKey, JSON.stringify(progress)); }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
function renderDashboard() {
  const done = labs.filter(lab => progress[lab.id]).length;
  document.querySelector('#progress-label').innerHTML = `${done} <small>/ ${labs.length} COMPLETE</small>`;
  document.querySelector('#progress-fill').style.width = `${done / labs.length * 100}%`;
  document.querySelector('#progress-message').textContent = done === labs.length ? `All ${labs.length} labs complete. Nice work.` : done ? `${done} lab${done === 1 ? '' : 's'} complete · keep going` : 'Pick a lab to get started';
  document.querySelector('#progress-steps').innerHTML = labs.map((lab, index) => `<i class="${index < done ? 'done' : ''}" aria-hidden="true"></i>`).join('');
  document.querySelector('#lab-grid').innerHTML = labs.map(lab => `
    <article class="lab-card">
      <div class="lab-card-top"><span class="lab-index">LAB / ${lab.number}</span><span class="lab-state ${progress[lab.id] ? 'complete' : ''}"><i></i>${progress[lab.id] ? 'COMPLETE' : 'NOT STARTED'}</span></div>
      <h3 class="lab-title">${escapeHtml(lab.title)}</h3><p class="lab-description">${escapeHtml(lab.description)}</p>
      <div class="lab-card-bottom"><span class="lab-tags">${escapeHtml(lab.tag)}</span><button class="open-lab" data-lab="${lab.id}">${progress[lab.id] ? 'REVISIT' : 'OPEN LAB'} <span>→</span></button></div>
    </article>`).join('');
}
function setResult(message, kind = '') {
  const box = document.querySelector('#lab-result');
  if (!box) return;
  box.className = `result-box ${kind}`;
  box.textContent = message;
}
function resultJson(data) { return JSON.stringify(data, null, 2); }
async function api(url, body) {
  const response = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The lab request did not succeed.');
  return data;
}
function completionBlock() {
  return progress[activeLab.id]
    ? '<div class="complete-banner"><span>✓ &nbsp; LAB COMPLETE</span><button data-action="revisit">Review this lab</button></div>'
    : '<div class="complete-banner" id="completion-banner" hidden><span>✓ &nbsp; OBJECTIVE COMPLETE</span><button data-action="complete">Save progress</button></div>';
}
function showCompletion() {
  const banner = document.querySelector('#completion-banner');
  if (banner) banner.hidden = false;
  if (activeMode === 'practice') {
    const details = {
      idor: 'You changed the profile ID in the URL and the server returned another user\'s private information. Real apps must check ownership for every requested object.',
      xss: 'Your harmless injected script executed inside the isolated training frame. Real apps should render user input as text or encode it for its output context.',
      sqli: 'Your input changed the SQL condition and returned multiple synthetic accounts. Parameterized queries prevent input from becoming SQL syntax.',
      auth: 'You used the predictable reset flow to access the synthetic admin account. Real reset tokens must be random, expiring, and single-use.',
      cmdi: 'The semicolon separated the simulated member lookup from a second allowlisted training action. Real apps should avoid passing user input through a shell.'
    };
    openNotice('success', 'Lab objective complete', details[activeLab.id]);
  }
}
function openNotice(kind, title, message) {
  noticeKind = kind;
  const modal = document.querySelector('#notice-modal');
  modal.querySelector('.notice-modal').classList.toggle('is-success', kind === 'success');
  document.querySelector('#notice-mark').textContent = kind === 'success' ? '✓' : '?';
  document.querySelector('#notice-eyebrow').textContent = kind === 'success' ? `${activeLab.short} · PRACTICE COMPLETE` : `${activeLab.short} · PRACTICE HINT`;
  document.querySelector('#notice-title').textContent = title;
  document.querySelector('#notice-message').textContent = message;
  document.querySelector('#notice-count').textContent = kind === 'hint' ? `HINT ${hintIndex + 1} OF ${activeLab.hints.length}` : '';
  document.querySelector('#notice-actions').innerHTML = kind === 'hint'
    ? `${hintIndex < activeLab.hints.length - 1 ? '<button class="hint-more" data-notice-action="more-hint">NEXT HINT →</button>' : ''}<button class="notice-close" data-notice-action="close">BACK TO LAB</button>`
    : '<button class="notice-close" data-notice-action="close">KEEP PRACTICING</button><button class="primary-button" data-notice-action="save">SAVE PROGRESS</button>';
  modal.hidden = false;
}
function showHint() {
  hintIndex = 0;
  const hint = activeLab.id === 'xss' && hintIndex === 1
    ? "For a harmless proof, enter <script>alert('XSS')</script>. It runs inside the isolated training frame."
    : activeLab.hints[hintIndex];
  openNotice('hint', 'A clue, not the answer', hint);
}
function closeNotice() { document.querySelector('#notice-modal').hidden = true; }
function taskList() {
  if (activeMode !== 'practice') return '';
  const tasks = {
    idor:['Open the profile endpoint','Access a different user\'s synthetic private note'],
    xss:['Inspect the reflected greeting','Trigger the sandboxed alert proof'],
    sqli:['Try a normal sign-in','Expose multiple synthetic account matches'],
    cmdi:['Run a normal member lookup','Expose the synthetic note with a second simulated command'],
    auth:['Reset the synthetic admin password','Sign in and retrieve the lab flag']
  }[activeLab.id];
  return `<ul class="task-list">${tasks.map((task, i) => `<li id="task-${i}">${escapeHtml(task)}</li>`).join('')}</ul>`;
}
function setTaskDone(index) { const task = document.querySelector(`#task-${index}`); if (task) task.classList.add('done'); }
function formForLab() {
  if (activeLab.id === 'idor') return `<div class="concept-callout">Training account: learner · Your profile URL ends in <strong>/1001</strong>. Edit the URL's number and press Go.</div><form class="url-browser" id="idor-form"><div class="browser-chrome"><i class="browser-dot"></i><i class="browser-dot"></i><i class="browser-dot"></i><div class="address-bar"><span>URL</span><input id="idor-url" aria-label="Practice profile URL" value="http://training.local/profile/1001" spellcheck="false"></div><button class="address-go" type="submit">GO</button></div><div class="profile-app" id="profile-result"><div class="profile-app-header"><strong>FIELDNOTES</strong><span>MY ACCOUNT · SIGNED IN</span></div><div class="profile-card"><div class="profile-avatar">AM</div><div><h4 class="profile-name">Avery Morgan</h4><div class="profile-meta">Learner · Profile 1001</div></div><div class="profile-private"><strong>PRIVATE NOTE</strong>Welcome to your practice account.</div></div><p class="app-shell-note">Synthetic training profile · local lab only</p></div></form><button class="hint-button" type="button" data-action="idor-hint">Need a hint?</button><div class="result-box" id="lab-result" aria-live="polite"></div>`;
  if (activeLab.id === 'xss') return `<div class="concept-callout">FIELDNOTES · Your personalized workspace preview is isolated in a sandbox. Network access is blocked.</div><form class="lab-form" id="xss-form"><label class="field-label">YOUR DISPLAY NAME<input id="xss-name" placeholder="e.g. Avery Morgan" autocomplete="off"></label><div class="button-row"><button class="primary-button" type="submit">OPEN MY WORKSPACE →</button><button class="hint-button" type="button" data-action="xss-hint">Need a hint?</button></div></form><iframe class="sandbox-frame" id="xss-frame" title="Isolated Fieldnotes workspace preview" sandbox="allow-scripts allow-modals" referrerpolicy="no-referrer"></iframe><div class="result-box" id="lab-result" aria-live="polite"></div>`;
  if (activeLab.id === 'sqli') return `<div class="concept-callout">FIELDNOTES WORKSPACE · Local sign-in demo using synthetic training accounts only.</div><div class="training-portal"><header class="training-portal-header"><div class="training-portal-brand"><span class="portal-mark">F</span><span>FIELDNOTES<small>WORKSPACE</small></span></div><span class="portal-local">LOCAL PORTAL</span></header><div class="training-portal-body"><span class="portal-kicker">MEMBER ACCESS</span><h4>Welcome back</h4><p class="portal-copy">Sign in to continue to your workspace.</p><form class="portal-login-form" id="sqli-form"><label class="field-label">USERNAME<input id="sqli-user" placeholder="e.g. mira" autocomplete="username"></label><label class="field-label">ACCESS PIN<input id="sqli-pin" type="password" inputmode="numeric" placeholder="Enter your PIN" autocomplete="current-password"></label><div class="portal-actions"><button class="primary-button" type="submit">SIGN IN TO WORKSPACE →</button><button class="hint-button" type="button" data-action="sqli-hint">Need a hint?</button></div></form><p class="portal-footnote">Training portal · Fictional accounts · Local only</p><div class="result-box" id="lab-result" aria-live="polite"></div></div></div>`;
  if (activeLab.id === 'cmdi') return `<div class="concept-callout">SAFE SIMULATOR · Command separators are modeled against fixed training actions. No operating-system commands or external targets are used.</div><div class="training-portal command-portal"><header class="training-portal-header"><div class="training-portal-brand"><span class="portal-mark">F</span><span>FIELDNOTES<small>OPERATIONS CONSOLE</small></span></div><span class="portal-local">LOCAL TRAINING</span></header><div class="training-portal-body"><span class="portal-kicker">DIRECTORY TOOLS</span><h4>Member lookup</h4><p class="portal-copy">Look up a synthetic team member in the training directory.</p><form class="portal-login-form" id="cmdi-form"><label class="field-label">USERNAME<input id="cmdi-user" placeholder="e.g. mira" autocomplete="off"></label><div class="portal-actions"><button class="primary-button" type="submit">RUN LOOKUP →</button><button class="hint-button" type="button" data-action="cmdi-hint">Need a hint?</button></div></form><div class="cmdi-terminal"><div class="cmdi-terminal-head"><span>SESSION OUTPUT</span><span>SIMULATED</span></div><pre id="cmdi-output" aria-live="polite">Ready. Enter a training username to begin.</pre></div><p class="portal-footnote">Synthetic directory · Fixed actions only · No shell process</p><div class="result-box" id="lab-result" aria-live="polite"></div></div></div>`;
  return `<div class="concept-callout">FIELDNOTES ACCOUNT SECURITY · A local recovery simulation using synthetic credentials only.</div><div class="training-portal auth-portal"><header class="training-portal-header"><div class="training-portal-brand"><span class="portal-mark">F</span><span>FIELDNOTES<small>ACCOUNT CENTER</small></span></div><span class="portal-local">LOCAL PORTAL</span></header><div class="auth-portal-body"><div class="auth-progress"><span class="current" id="auth-step-reset"><b>01</b> RESET PASSWORD</span><span id="auth-step-login"><b>02</b> SIGN IN</span></div><section class="auth-flow-card"><span class="portal-kicker">ACCOUNT RECOVERY</span><h4>Reset your password</h4><p class="portal-copy">Enter the training recovery token and choose a new practice password.</p><form class="portal-login-form" id="auth-reset-form"><label class="field-label">ACCOUNT<input id="auth-account" value="admin" autocomplete="username"></label><label class="field-label">RECOVERY TOKEN<input id="auth-token" placeholder="Enter recovery token" autocomplete="off"></label><label class="field-label">NEW PASSWORD<input id="auth-new" placeholder="Choose a practice-only password" autocomplete="new-password"></label><div class="portal-actions"><button class="primary-button" type="submit">SET NEW PASSWORD →</button><button class="hint-button" type="button" data-action="auth-hint">Need a hint?</button></div></form></section><section class="auth-flow-card auth-login-panel" id="auth-login-panel" hidden><span class="portal-kicker">STEP 02 · SIGN IN</span><h4>Your password is updated</h4><p class="portal-copy">Sign in with the new practice password to finish the challenge.</p><form class="portal-login-form" id="auth-login-form"><label class="field-label">USERNAME<input id="auth-login-user" value="admin" autocomplete="username"></label><label class="field-label">PASSWORD<input id="auth-login-pass" placeholder="Enter your new password" autocomplete="current-password"></label><div class="portal-actions"><button class="primary-button" type="submit">SIGN IN SECURELY →</button></div></form></section><p class="portal-footnote">Synthetic account · No email or external service is used</p><div class="result-box" id="lab-result" aria-live="polite"></div></div></div>`;
}
function renderStage() {
  const walkthrough = activeMode === 'walkthrough';
  const practiceCopy = activeLab.id === 'auth'
    ? 'Follow the recovery flow: reset the synthetic admin password, then sign in with your new practice password.'
    : 'Complete the objective using the local training endpoint. Hints are available, and your progress stays in this browser.';
  document.querySelector('.lab-workspace').classList.toggle('walkthrough-full', walkthrough);
  document.querySelector('#lesson-steps').innerHTML = '';
  document.querySelector('#field-note').textContent = activeLab.note;
  const walkthroughContent = walkthrough
    ? `<div class="stage-kicker">COMPLETE WALKTHROUGH</div><h3 class="stage-title">Understand ${escapeHtml(activeLab.short)}</h3><div class="walkthrough-content">${activeLab.steps.map(([heading, copy]) => `<div class="walkthrough-part"><h4>${escapeHtml(heading)}</h4><p>${escapeHtml(copy)}</p></div>`).join('')}</div><details class="walkthrough-help"><summary>Need help solving this lab?</summary><ol>${activeLab.solution.map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol></details><div class="button-row" style="margin-top:10px"><button class="primary-button" data-action="go-practice">TRY IT IN PRACTICE →</button></div>`
    : `<div class="stage-kicker">PRACTICE OBJECTIVE</div><h3 class="stage-title">Your turn: ${escapeHtml(activeLab.short)}</h3><p class="stage-copy">${escapeHtml(practiceCopy)}</p>${taskList()}${formForLab()}${completionBlock()}`;
  document.querySelector('#lab-stage').innerHTML = walkthroughContent;
  bindLabForm();
}
function bindLabForm() {
  document.querySelector('#idor-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    const url = document.querySelector('#idor-url').value.trim();
    const match = url.match(/\/profile\/(\d+)\/?(?:\?.*)?$/);
    if (!match) { setResult('Use a practice profile URL that ends with /profile/<number>.', 'error'); return; }
    const id = match[1];
    try {
      const response = await fetch(`/api/idor/profile?user_id=${encodeURIComponent(id)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      document.querySelector('#profile-result').innerHTML = `<div class="profile-app-header"><strong>FIELDNOTES</strong><span>MY ACCOUNT · SIGNED IN</span></div><div class="profile-card"><div class="profile-avatar">${escapeHtml(data.name.split(' ').map(part => part[0]).join('').slice(0, 2))}</div><div><h4 class="profile-name">${escapeHtml(data.name)}</h4><div class="profile-meta">${escapeHtml(data.plan)} · Profile ${escapeHtml(data.id)}</div></div><div class="profile-private"><strong>PRIVATE NOTE</strong>${escapeHtml(data.private_note)}</div></div><p class="app-shell-note">Synthetic training profile · local lab only</p>`;
      const output = document.querySelector('#lab-result');
      output.className = 'result-box';
      output.textContent = `Profile loaded from /profile/${data.id}. The page now displays ${data.name}'s synthetic training profile.`;
      setTaskDone(0);
      if (String(data.id) !== '1001' && data.private_note !== 'Welcome to your practice account.') {
        setTaskDone(1);
        output.classList.add('success');
        showCompletion();
      }
    } catch (error) { setResult(error.message, 'error'); }
  });
  document.querySelector('#xss-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    xssProofReceived = false;
    const name = document.querySelector('#xss-name').value;
    try {
      const response = await fetch(`/api/xss/render?name=${encodeURIComponent(name)}`);
      const data = await response.json();
      const frame = document.querySelector('#xss-frame');
      const policy = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; frame-src 'none'; base-uri 'none'">`;
      const siteStyle = `<style>
        *{box-sizing:border-box}html,body{margin:0;min-height:100%;font:13px 'Segoe UI',sans-serif;color:#23342d;background:#f1f4ef}
        .site-shell{min-height:300px;display:grid;grid-template-columns:116px 1fr}.site-sidebar{padding:15px 10px;background:#20352c;color:#f4f5ef;display:flex;flex-direction:column;gap:18px}
        .site-brand{font-size:11px;font-weight:700;letter-spacing:1px}.site-nav{display:grid;gap:7px}.site-nav span{padding:7px 8px;color:#c6d1c8;font-size:10px}.site-nav .current{background:#344e40;color:#d5efb7}.site-local{margin-top:auto;color:#b7c9bb;font-size:8px;line-height:1.5}
        .site-main{padding:17px 20px}.site-topbar{display:flex;justify-content:space-between;align-items:center;padding-bottom:13px;border-bottom:1px solid #dce3da;color:#69766c;font-size:9px}.site-user{display:flex;align-items:center;gap:6px}.site-avatar{display:grid;place-items:center;width:23px;height:23px;border-radius:50%;background:#deebd2;color:#45623c;font-size:9px;font-weight:700}
        .site-kicker{margin:19px 0 5px;color:#78867a;font-size:8px;letter-spacing:1px}.site-main h1{margin:0 0 13px;font-size:19px;font-weight:600}.welcome-panel{display:flex;align-items:flex-start;gap:11px;padding:16px;background:#fff;border:1px solid #e0e6de;border-radius:3px;box-shadow:0 5px 16px #263b2b0b}.welcome-icon{flex:0 0 34px;height:34px;display:grid;place-items:center;background:#e8f0df;color:#4b6841;border-radius:50%;font-size:10px;font-weight:700}.welcome-copy{min-width:0}.welcome-copy h2{margin:1px 0 6px;font-size:15px;font-weight:600}.welcome-copy p{margin:0;color:#748076;font-size:10px;line-height:1.5}
        .site-lower{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:10px}.site-lower div{padding:10px;background:#fff;border:1px solid #e0e6de;color:#758177;font-size:9px}.site-lower strong{display:block;margin-bottom:4px;color:#34463a;font-size:9px}
        @media(max-width:430px){.site-shell{grid-template-columns:1fr}.site-sidebar{display:none}.site-main{padding:14px}}
      </style>`;
      const alertHook = `<script>(function(){const nativeAlert=window.alert.bind(window);window.alert=function(message){nativeAlert(message);parent.postMessage({type:'vulnlab-xss-proof',marker:'sandbox-script-ran'},'*')}})()</script>`;
      frame.srcdoc = `${policy}${siteStyle}<div class="site-shell"><aside class="site-sidebar"><div class="site-brand">FIELDNOTES</div><nav class="site-nav"><span class="current">Workspace</span><span>Messages</span><span>Saved</span><span>Settings</span></nav><div class="site-local">LOCAL PREVIEW<br>TRAINING DATA</div></aside><main class="site-main"><header class="site-topbar"><span>MY WORKSPACE</span><span class="site-user"><span class="site-avatar">AM</span> Avery Morgan</span></header><div class="site-kicker">HOME / OVERVIEW</div><h1>Your workspace</h1><section class="welcome-panel"><span class="welcome-icon">FN</span><div class="welcome-copy">${alertHook}${data.html}</div></section><div class="site-lower"><div><strong>RECENT ACTIVITY</strong>Your workspace is up to date.</div><div><strong>QUICK NOTE</strong>Your practice content is local and synthetic.</div></div></main></div>`;
      setResult('Rendered inside a sandboxed frame. Try the harmless proof from the hint button.', '');
      setTaskDone(0);
    } catch (error) { setResult(error.message, 'error'); }
  });
  document.querySelector('#sqli-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const data = await api('/api/sqli/search', {username:document.querySelector('#sqli-user').value, pin:document.querySelector('#sqli-pin').value});
      const output = document.querySelector('#lab-result');
      output.className = 'result-box';
      output.innerHTML = `<div class="portal-result-heading"><strong>${data.count > 1 ? 'Multiple accounts matched' : data.count === 1 ? 'Account matched' : 'No account matched'}</strong><span>${data.count} MATCH${data.count === 1 ? '' : 'ES'}</span></div>${data.count ? `<ul class="portal-account-list">${data.results.map(account => `<li><strong>${escapeHtml(account.display_name)}</strong><span>${escapeHtml(account.username)} · ${escapeHtml(account.department)}</span></li>`).join('')}</ul>` : '<p class="portal-empty">Check the username and PIN, then try again.</p>'}`;
      setTaskDone(0);
      if (data.count > 1) { setTaskDone(1); output.classList.add('success'); showCompletion(); }
    } catch (error) { setResult(error.message, 'error'); }
  });
  document.querySelector('#cmdi-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const data = await api('/api/cmdi/run', {username:document.querySelector('#cmdi-user').value});
      document.querySelector('#cmdi-output').textContent = data.results.map(result => `$ ${result.command}\n${result.output}`).join('\n\n');
      setTaskDone(0);
      if (data.note_exposed) {
        setTaskDone(1);
        document.querySelector('#lab-result').className = 'result-box success';
        document.querySelector('#lab-result').textContent = 'The simulator accepted the extra allowlisted training action.';
        showCompletion();
      }
    } catch (error) { setResult(error.message, 'error'); }
  });
  document.querySelector('#auth-reset-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const data = await api('/api/auth/reset-password', {username:document.querySelector('#auth-account').value, token:document.querySelector('#auth-token').value, new_password:document.querySelector('#auth-new').value});
      setResult(data.message, 'success');
      document.querySelector('#auth-login-panel').hidden = false;
      document.querySelector('#auth-step-reset').classList.add('done');
      document.querySelector('#auth-step-login').classList.add('current');
      if (document.querySelector('#auth-account').value === 'admin') setTaskDone(0);
    } catch (error) { setResult(error.message, 'error'); }
  });
  document.querySelector('#auth-login-form')?.addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const data = await api('/api/auth/login', {username:document.querySelector('#auth-login-user').value, password:document.querySelector('#auth-login-pass').value});
      const output = document.querySelector('#lab-result');
      output.className = 'result-box success';
      output.innerHTML = `<strong>${escapeHtml(data.message)}</strong>${data.flag ? `<pre>${escapeHtml(data.flag)}</pre>` : ''}`;
      document.querySelector('#auth-step-login').classList.add('done');
      if (data.flag) { setTaskDone(1); showCompletion(); }
    } catch (error) { setResult(error.message, 'error'); }
  });
}
window.addEventListener('message', event => {
  if (!activeLab || activeLab.id !== 'xss' || event.source !== document.querySelector('#xss-frame')?.contentWindow) return;
  if (event.data?.type === 'vulnlab-xss-proof' && event.data?.marker === 'sandbox-script-ran') {
    xssProofReceived = true;
    setTaskDone(1);
    setResult('XSS confirmed: injected script ran inside the opaque-origin sandbox and posted its harmless proof.', 'success');
    showCompletion();
  }
});
function openLab(id) {
  activeLab = labs.find(lab => lab.id === id);
  activeMode = 'walkthrough'; xssProofReceived = false;
  document.querySelector('#modal-category').textContent = activeLab.category;
  document.querySelector('#modal-title').textContent = activeLab.title;
  document.querySelector('#modal-description').textContent = activeLab.description;
  document.querySelector('#modal-eyebrow').textContent = `LAB ${activeLab.number} · ${activeLab.category}`;
  document.querySelectorAll('.mode-tab').forEach(tab => { const selected = tab.dataset.mode === activeMode; tab.classList.toggle('active', selected); tab.setAttribute('aria-selected', String(selected)); });
  renderStage();
  document.querySelector('#lab-modal').hidden = false;
  document.body.style.overflow = 'hidden';
}
function closeLab() { document.querySelector('#lab-modal').hidden = true; document.body.style.overflow = ''; activeLab = null; }
document.querySelector('#lab-grid').addEventListener('click', event => { const button = event.target.closest('[data-lab]'); if (button) openLab(button.dataset.lab); });
document.querySelector('#close-modal').addEventListener('click', closeLab);
document.querySelector('#lab-modal').addEventListener('click', event => { if (event.target.id === 'lab-modal') closeLab(); });
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if (!document.querySelector('#notice-modal').hidden) closeNotice();
  else if (activeLab) closeLab();
});
document.querySelector('#notice-modal').addEventListener('click', event => {
  if (event.target.id === 'notice-modal') { closeNotice(); return; }
  const action = event.target.closest('[data-notice-action]')?.dataset.noticeAction;
  if (action === 'close') closeNotice();
  if (action === 'more-hint') { hintIndex += 1; openNotice('hint', 'A clue, not the answer', activeLab.hints[hintIndex]); }
  if (action === 'save') {
    progress[activeLab.id] = true;
    saveProgress();
    renderDashboard();
    closeNotice();
    const banner = document.querySelector('#completion-banner');
    if (banner) banner.innerHTML = '<span>✓ &nbsp; LAB COMPLETE</span>';
  }
});
document.querySelectorAll('.mode-tab').forEach(tab => tab.addEventListener('click', () => { activeMode = tab.dataset.mode; document.querySelectorAll('.mode-tab').forEach(item => { const selected = item === tab; item.classList.toggle('active', selected); item.setAttribute('aria-selected', String(selected)); }); renderStage(); }));
document.querySelector('#lab-stage').addEventListener('click', event => {
  const action = event.target.closest('[data-action]')?.dataset.action;
  if (!action) return;
  if (action && action.endsWith('-hint')) { showHint(); return; }
  if (action === 'go-practice') { document.querySelector('.mode-tab[data-mode="practice"]').click(); return; }
  if (action === 'complete') { progress[activeLab.id] = true; saveProgress(); renderDashboard(); renderStage(); }
  if (action === 'revisit') { activeMode = 'practice'; document.querySelector('.mode-tab[data-mode="practice"]').click(); return; }
  if (action === 'previous-step' || action === 'next-step') { renderStage(); return; }
});
document.querySelector('#reset-progress').addEventListener('click', () => { progress = Object.fromEntries(labs.map(lab => [lab.id, false])); saveProgress(); renderDashboard(); });

function applyTheme(theme) {
  const normalizedTheme = theme === 'dark' ? 'dark' : 'light';
  document.body.dataset.theme = normalizedTheme;
  const toggle = document.querySelector('#theme-toggle');
  if (toggle) {
    toggle.setAttribute('aria-pressed', String(normalizedTheme === 'dark'));
    toggle.querySelector('.theme-toggle-text').textContent = normalizedTheme === 'dark' ? 'Dark mode' : 'Light mode';
  }
  localStorage.setItem('vulnlab-theme', normalizedTheme);
}

const savedTheme = localStorage.getItem('vulnlab-theme') || 'dark';
applyTheme(savedTheme);
document.querySelector('#theme-toggle').addEventListener('click', () => {
  applyTheme(document.body.dataset.theme === 'dark' ? 'light' : 'dark');
});
renderDashboard();
