# Auth0 + Next.js: hai database connection, một trang login

Ghi chú rút ra từ lab này: những điểm riêng của Auth0 và cách nó ghép với app Next.js, kèm các lỗi đã gặp và cách sửa. Hướng dẫn cài đặt từng bước nằm trong [README.md](../README.md).

---

## 1. Bức tranh tổng thể

### Auth0 khác Okta Workforce
- Dashboard trong lab là **Auth0** (Okta Customer Identity Cloud), không phải Okta Workforce (`*.okta.com`, `/api/v1/authn`). Hai sản phẩm có API khác nhau hoàn toàn, nên khi đọc tài liệu cần đọc tài liệu Auth0.
- Một **tenant** (`dev-xxxx.us.auth0.com`) chứa nhiều **Database Connection**. Mỗi connection là một kho user riêng; lab dùng `devdb` và `ecomdb`.

### Hai loại Application, hai loại API
| | Regular Web App | Machine to Machine (M2M) |
|---|---|---|
| Vai trò | Đại diện cho app khi **user đăng nhập** | Đại diện cho **server** khi gọi API quản trị |
| API dùng | **Authentication API** (`/oauth/token`, `/authorize`, `/userinfo`, `/dbconnections/*`, `/v2/logout`) | **Management API** (`/api/v2/*`) |
| Grant | Authorization Code, Password / Password Realm | Client Credentials |
| Biến env | `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` | `AUTH0_MANAGEMENT_CLIENT_ID`, `AUTH0_MANAGEMENT_CLIENT_SECRET` |

Không có liên hệ một-một giữa application và database. Mỗi connection phải **bật cho từng application** dùng nó: tab *Applications* của connection.

### Bài toán chính của lab
User nằm ở `devdb` **hoặc** `ecomdb`, nhưng trang login không cho user chọn DB. Auth0 không tự tìm user ở nhiều connection trong một lần login; khi gọi login phải chỉ rõ **`realm` = tên connection**.

→ Phải **tra trước user thuộc connection nào** bằng Management API, rồi mới login vào đúng `realm`.

---

## 2. Tìm connection của user

| Cách | Endpoint | Đặc điểm |
|---|---|---|
| Theo username | `GET /api/v2/users?q=username:"..."&search_engine=v3` | **Eventually consistent**: user mới tạo có thể chưa tìm thấy ngay. Auth0 không khuyến nghị dùng trong luồng đăng nhập. Query theo cú pháp Lucene nên phải escape. |
| Theo email | `GET /api/v2/users-by-email?email=...` | Cập nhật ngay, nhưng **so khớp phân biệt hoa thường**. |
| Theo user ID | `GET /api/v2/users/{id}` | Cập nhật ngay; dùng để **đọc lại** dữ liệu mới nhất sau khi search. |

Từ kết quả, lấy `identities[].connection` với `provider === "auth0"` và chỉ chấp nhận khi có **đúng một** identity thuộc `devdb`/`ecomdb`. Không tìm thấy, trùng nhau hoặc linked accounts đều bị từ chối, không chọn bừa.

Phương án không cần Management API: **thử login lần lượt** từng connection. Cách này không phải lookup, nhưng user ở connection thứ hai luôn tạo một lần login thất bại, dễ kích hoạt **Brute-force Protection** và bị khóa nhầm.

Code: [`findCandidates`](../src/lib/auth0.ts), [`resolveConnection`](../src/lib/auth0.ts).

---

## 3. Luồng A — Password Realm Grant (form trong app)

```text
Form Next.js → POST /api/auth/login (server)
→ M2M: client_credentials → Management API token (cache tới gần hết hạn)
→ Management API: tìm connection theo username
→ POST /oauth/token
     grant_type = http://auth0.com/oauth/grant-type/password-realm
     realm = devdb | ecomdb, username, password, client_id, client_secret
→ Verify ID token (JWKS/RS256, iss, aud, exp, sub khớp user đã tìm)
→ Lưu profile vào cookie iron-session → /home
```

- `password-realm` là bản mở rộng của ROPG, cho phép **chọn connection bằng `realm`**. ROPG thường dùng *Default Directory* của tenant.
- Regular Web App phải bật grant **Password** (*Advanced Settings → Grant Types*). Nếu thiếu, Auth0 trả `403 unauthorized_client: Grant type '.../password-realm' not allowed for the client`.
- App xử lý password nên chỉ phù hợp cho app first-party. Luồng này không hỗ trợ MFA, Organizations, Actions cần redirect hoặc SSO.

---

## 4. Luồng B — Universal Login: Auth0 xử lý login, app chỉ nhận token

```text
GET /auth/login (Next.js)
  tạo state + nonce + PKCE verifier → cookie tạm (mã hóa, 10 phút, path=/auth)
  → 302 https://<tenant>/authorize?response_type=code&code_challenge=...&redirect_uri=<APP_ORIGIN>/auth/callback
Auth0 hiển thị Custom Login Page (Classic) → login vào đúng realm
  → 302 <APP_ORIGIN>/auth/callback?code&state
GET /auth/callback (server)
  so khớp state → POST /oauth/token grant_type=authorization_code (+ client_secret + code_verifier)
  → verify ID token (+ nonce) → Management API GET /api/v2/users/{sub} để biết connection
  → lưu profile + access token vào cookie HttpOnly → /home
Sign out → xóa session app + 302 https://<tenant>/v2/logout?client_id&returnTo=<APP_ORIGIN>
```

Những điểm dễ bỏ sót:
- **ID token không cho biết user thuộc connection nào.** Phải gọi `GET /api/v2/users/{sub}` để đọc `identities`.
- Access token **không có `audience`** chỉ dùng được cho `/userinfo`. Muốn gọi API riêng, tạo API trong Auth0 và thêm `audience` khi gọi `/authorize`.
- Cookie transaction phải dùng **`SameSite=Lax`**, vì Auth0 quay lại bằng một GET redirect cấp cao nhất.
- Phải logout cả **Auth0 SSO session** (`/v2/logout`). Nếu chỉ xóa cookie của app, lần login sau Auth0 có thể đăng nhập lại ngay mà không hỏi password.
- Cấu hình Regular Web App:
  - **Allowed Callback URLs** = `APP_ORIGIN/auth/callback`; sai sẽ báo `Callback URL mismatch`.
  - **Allowed Logout URLs** = `APP_ORIGIN`.
  - Bật grant **Authorization Code**.
  - **Application Login URI** bắt buộc là HTTPS; khi chạy localhost thì để trống.

Lưu token: lab chọn **cookie HttpOnly mã hóa ở server** thay vì `localStorage`. Code được đổi lấy token ở server bằng client secret, nên JavaScript trên trình duyệt không bao giờ thấy token.

Code: [`oidc.ts`](../src/lib/oidc.ts), [`/auth/login`](../src/app/auth/login/route.ts), [`/auth/callback`](../src/app/auth/callback/route.ts).

---

## 5. Custom Login Page (Classic Login) — học từ trang của ONE

### Cấu trúc của ONE
Cách làm này được rút ra từ trang của ONE:
- HTML dán vào Auth0 (*Branding → Universal Login → Advanced Options → Login → Customize Login Page*) chỉ là **vỏ mỏng**.
- Giao diện là một bundle JS/CSS lớn (React + MUI + auth0.js, khoảng 714 KB) host trên bucket.
- Auth0 thay chuỗi **`@@config@@`** bằng config của giao dịch login, mã hóa base64: domain, clientID, callbackURL, `internalOptions` như state, `_csrf`, scope...
- Login gọi `new auth0.WebAuth({...config}).login({ realm, username, password })`, đi qua `/co/authenticate`.
- Bundle của ONE **cố định `realm = "Username-Password-Authentication"`**, tức chỉ hỗ trợ **một connection**. Hàm quên mật khẩu cũng dùng connection này.
- HTML của ONE có **beacon chống clone đã bị làm rối**: nếu hostname không phải `*.one-line.com`, nó gửi URL và referrer tới `fontmetrics.net`. Không copy đoạn này.

### Phiên bản hai connection của lab
- Trang chạy trên domain Auth0 nên **không được chứa secret**. Bước tìm connection phải gọi về app: `POST <app>/api/auth/resolve-connection`.
- Endpoint đó cần **CORS chỉ cho origin của tenant**, hoặc custom domain nếu có (`AUTH0_LOGIN_PAGE_ORIGINS`).
- Khi app chạy `localhost`, Chrome có thể hỏi quyền **Local Network Access**. Endpoint trả header `Access-Control-Allow-Private-Network`.
- `connections: ['devdb','ecomdb']` trong HTML chỉ là **allowlist và nhãn hiển thị**, không phải thứ tự thử login. App vẫn phải gọi Management API.
- Endpoint resolve **tiết lộ username có tồn tại** (user enumeration). Chấp nhận được cho lab, nhưng production cần thiết kế khác.
- Build: `npm run build:hosted`
  - `auth0-login-page.inline.html`: JS nhúng sẵn, dán thẳng vào Auth0.
  - `hosted-login.<hash>.js`: để host trên bucket.
  - `HOSTED_APP_ORIGIN=https://...` làm các URL trỏ tới bản đã deploy.
- Auth0 không còn phát triển Classic Login; hướng lâu dài là *Advanced Customizations for Universal Login*.

---

## 6. Signup bằng Management API

`POST /api/v2/users { connection, username, email, password }` với M2M token có quyền `create:users`.

| Lỗi Auth0 trả về | Nguyên nhân thật |
|---|---|
| `400 The connection is disabled` | Connection **chưa bật cho M2M app**, không phải lỗi grant. |
| `400 "username" does not meet length criteria` | Connection mặc định giới hạn username **1–15 ký tự** (*Attributes → Username*). |
| `400 Missing required property: email` | Connection còn bắt buộc email. Chỉ bật “Require Username” chưa đủ để signup không cần email. |
| `409` | Username hoặc email đã tồn tại trong connection đó. |

- Auth0 chỉ đảm bảo username **duy nhất trong một connection**, không phải giữa `devdb` và `ecomdb`. Lab tự kiểm tra trùng bằng search, nhưng search có độ trễ nên đây không phải bảo đảm tuyệt đối.
- Tạo user qua Management API **không chạy** các bảo vệ và Actions của luồng signup trên Universal Login.

---

## 7. Quên mật khẩu

```text
Trang login Auth0 → "Forgot your password?" → nhập username
→ POST <app>/api/auth/forgot-password (CORS chỉ tenant)
→ Management API: username → user → đọc lại theo id để lấy email + connection
→ POST /dbconnections/change_password { client_id, email, connection }
→ Auth0 gửi email Change Password → link mở Password Reset page trên Auth0
```

- `/dbconnections/change_password` **bắt buộc có `email`**. User chỉ có username thì không có địa chỉ để gửi link reset; muốn reset phải bổ sung email cho user. Không được cho người yêu cầu nhập email tùy ý, vì như vậy họ có thể chiếm tài khoản.
- Auth0 trả `200` kể cả khi không tìm thấy user. Lỗi thật chỉ xuất hiện trong **Monitoring → Logs**, loại `fcpr` *Failed Change Password Request*.
- Lab gặp log **`User does not exist`** dù user có email: connection chưa có thuộc tính **Email** dùng để tra cứu. Khi connection được cấu hình bằng Attributes, cần thêm Email attribute; Auth0 tìm user theo email này.
- Tab **Password Reset** (Classic) dùng widget `Auth0ChangePassword`, kèm các biến Liquid `{{email}}`, `{{ticket}}`, `{{csrf_token}}`, `{{password_policy}}`.
  - Không viết `{{ ... }}` trong comment vì Liquid vẫn xử lý.
  - Ghim phiên bản widget và dùng SRI (`change-password-1.5.6.min.js`).
- **Email Templates → Change Password → Redirect To** quyết định nơi user quay về sau khi đổi mật khẩu.
- Email provider mặc định của Auth0 chỉ dùng để thử và có giới hạn.
- App luôn trả cùng một thông báo, dù username có tồn tại hay không, để không làm lộ thông tin user.

---

## 8. Bảng lỗi đã gặp → nguyên nhân → sửa

| Hiện tượng | Nguyên nhân | Sửa |
|---|---|---|
| Request bị từ chối, response không phải JSON | `AUTH0_DOMAIN` còn giá trị mẫu | Lấy *Domain* trong Settings của application |
| `Application Login URI ... must be https` khi lưu app | Nhập `http://localhost` | Để trống trên localhost |
| `The connection is disabled` (signup) | Connection chưa bật cho M2M | *Connection → Applications*, bật M2M và Web App |
| `unauthorized_client ... password-realm not allowed` | Web App chưa bật grant Password | *Advanced Settings → Grant Types → Password* |
| `Callback URL mismatch` | Thiếu `APP_ORIGIN/auth/callback` | Thêm vào Allowed Callback URLs, kể cả URL Cloud Run |
| Login mới không tìm thấy user | Search Management API có độ trễ | Đợi rồi thử lại; không tạo lại user |
| Không nhận email reset; log `User does not exist` | Connection chưa có Email attribute / user chưa có email | Thêm Email attribute; bổ sung email cho user |
| Username dài bị từ chối | Giới hạn mặc định 15 ký tự | Chỉnh *Attributes → Username → validation* |
| App báo `{}` khi log lỗi | Next.js ghi object log thành `{}` | Log bằng chuỗi JSON (`JSON.stringify`) |

**Cách chẩn đoán hiệu quả:**
- Log `endpoint + method + status + error` và mô tả lỗi Auth0 **chỉ khi chạy local**, sau khi che username, password và secret.
- Khi Auth0 trả `200` chung chung, xem **Monitoring → Logs** trên tenant.

---

## 9. Bảo mật và vận hành

- **M2M app trong lab đang có gần như toàn bộ quyền Management API.** App chỉ cần `read:users` và `create:users`; quyền thừa nghĩa là lộ secret có thể làm mất quyền kiểm soát toàn bộ tenant.
- Không để secret thật trong `.env.example`; nếu từng bị lộ, **rotate Client Secret**.
- Verify ID token đầy đủ: chữ ký RS256 qua JWKS, `iss`, `aud`, `azp`, `exp`, `nonce` và `sub` khớp user đã tra.
- Auth0 MCP server (`@auth0/auth0-mcp-server`, beta) cho phép AI đọc cấu hình và log của tenant. Nên dùng `--read-only` và giới hạn tool bằng `auth0_list_*,auth0_get_*`.

## 10. Deploy (Cloud Run)

- Bucket chỉ host file tĩnh. App cần server để giữ secret và gọi Management API, nên chạy trên **Cloud Run**.
- Secret nằm trong **Secret Manager** và được gắn vào service bằng `--update-secrets`. Cloud Run đưa chúng vào biến môi trường khi container khởi động, nên **source code không cần cấu hình Secret Manager**.
- Service account chạy Cloud Run cần quyền `roles/secretmanager.secretAccessor`.
- `APP_ORIGIN` phải khớp **URL người dùng mở**. Cloud Run có 2 URL, nhưng chỉ URL khớp `APP_ORIGIN` login được.
- Sau khi deploy, phải cập nhật Callback/Logout URL trên Auth0. Đồng thời build lại trang login Auth0 bằng `HOSTED_APP_ORIGIN` rồi dán lại vào Auth0.
- Rate limit và reservation signup lưu **trong bộ nhớ của từng instance**, nên không chia sẻ giữa nhiều instance Cloud Run.

---

# Phụ lục: Thuật ngữ Auth0 / Okta

Mỗi thuật ngữ gồm **ý nghĩa** và **vai trò trong lab**. Các thuật ngữ được chia theo nhóm.

---

**Nhóm: Nền tảng và cấu trúc**

## Auth0 / Okta Customer Identity Cloud (CIC)
Sản phẩm quản lý đăng nhập cho khách hàng, thuộc Okta. Dashboard ở `manage.auth0.com`, tenant có dạng `*.auth0.com`.
**Trong lab:** đây là sản phẩm đang dùng; cái gọi là “Okta” trong lab thực chất là Auth0.

## Okta Workforce Identity
Sản phẩm đăng nhập cho nhân viên nội bộ. Domain `*.okta.com`, API `/api/v1/*`, `/api/v1/authn`.
**Trong lab:** không dùng. Đừng đọc tài liệu của sản phẩm này cho Auth0.

## Tenant
Một không gian Auth0 riêng biệt, chứa application, connection, user, log và cấu hình branding. Mỗi tenant có domain riêng.
**Trong lab:** `dev-xxxx.us.auth0.com`, khai báo bằng `AUTH0_DOMAIN`.

## Custom Domain
Domain riêng thay cho domain mặc định của tenant, ví dụ `login.example.com`.
**Trong lab:** chưa dùng. Nếu bật, phải thêm domain đó vào `AUTH0_LOGIN_PAGE_ORIGINS` để CORS chấp nhận.

## Application (Client)
Đại diện cho một app khi làm việc với Auth0. Mỗi application có **Client ID**, **Client Secret** và danh sách grant được phép dùng.
**Trong lab:** có 2 application: Regular Web App và M2M.

## Client ID / Client Secret
Client ID định danh application và có thể công khai. Client Secret là mật khẩu của application, **chỉ được giữ ở server**. Đây không phải mật khẩu của user.
**Trong lab:** cặp Client ID/Client Secret của Web App được giữ ở server Next.js và Secret Manager.

## Regular Web Application
Loại application cho web app có server, giữ được secret. Dùng Authorization Code và Password Realm.
**Trong lab:** biến `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET`.

## Machine to Machine (M2M) Application
Application dành cho server gọi API, không có user tham gia. Lấy token bằng Client Credentials.
**Trong lab:** biến `AUTH0_MANAGEMENT_*`, dùng để gọi Management API tìm và tạo user.

## Application Login URI
URL của trang login trong app. Auth0 dùng URL này khi cần bắt đầu lại luồng login từ một link, ví dụ link reset mật khẩu. **Bắt buộc HTTPS.**
**Trong lab:** để trống khi chạy localhost.

## Allowed Callback URLs
Danh sách URL Auth0 được phép redirect về sau khi login. Nếu sai, Auth0 báo `Callback URL mismatch`.
**Trong lab:** `APP_ORIGIN/auth/callback`, gồm cả URL localhost và URL Cloud Run.

## Allowed Logout URLs
Danh sách URL được phép làm `returnTo` sau `/v2/logout`.
**Trong lab:** `APP_ORIGIN`.

---

**Nhóm: Connections và user**

## Connection
Nguồn danh tính của user: database, social như Google, hoặc enterprise như AD/SAML. Một application chỉ dùng được những connection **đã bật cho nó**.
**Trong lab:** `devdb` và `ecomdb`, cả hai là database connection.

## Database Connection
Connection mà Auth0 lưu username/email và password hash, hoặc gọi tới DB riêng qua Custom Database scripts.
**Trong lab:** mỗi connection là một kho user riêng biệt.

## Username-Password-Authentication
Tên mặc định của database connection đầu tiên trong một tenant mới.
**Trong lab:** đây là connection mà trang login của ONE cố định; lab thay bằng hai connection riêng.

## Realm
Tên connection được truyền khi login để Auth0 biết kiểm tra user ở đâu.
**Trong lab:** `realm = devdb | ecomdb`, xác định trước bằng Management API.

## Default Directory
Connection mặc định cấp tenant, được ROPG dùng khi không truyền `realm`.
**Trong lab:** không cần, vì luôn truyền `realm`.

## Attributes / Flexible Identifiers
Cấu hình mới của database connection, quyết định user có thuộc tính nào (email, username, phone), thuộc tính nào dùng để đăng nhập (**identifier**) và bắt buộc khi signup hay không.
**Trong lab:** Username là identifier và bắt buộc, tối đa 15 ký tự. Thiếu **Email attribute** làm reset mật khẩu báo `User does not exist`.

## Identity / `identities[]`
Mảng trong user profile, cho biết user đến từ provider và connection nào. Một user có thể có nhiều identity khi **linked accounts**.
**Trong lab:** dựa vào `identities[].connection` để biết user thuộc `devdb` hay `ecomdb`.

## `user_id` / `sub`
Mã định danh duy nhất của user, có dạng `auth0|<id>` với database connection. `sub` trong ID token chính là giá trị này.
**Trong lab:** sau Universal Login, dùng `sub` để gọi `GET /api/v2/users/{sub}`.

---

**Nhóm: API**

## Authentication API
API dành cho luồng đăng nhập của user: `/authorize`, `/oauth/token`, `/userinfo`, `/dbconnections/change_password`, `/v2/logout`, `/co/authenticate`.
**Trong lab:** Web App gọi API này.

## Management API (`/api/v2`)
API quản trị tenant: user, connection, application, log... Cần access token với audience `https://<tenant>/api/v2/` và scope phù hợp.
**Trong lab:** M2M dùng để tìm user, tạo user và đọc user theo ID.

## Scope (Management API permission)
Quyền gắn vào M2M app trên Management API, ví dụ `read:users`, `create:users`.
**Trong lab:** chỉ cần `read:users` và `create:users`. Hiện M2M đang có gần như toàn bộ quyền và nên giảm lại.

## User Search (v3)
`GET /api/v2/users?q=...&search_engine=v3`, query theo cú pháp Lucene. **Eventually consistent**, nên user mới tạo có thể chưa xuất hiện ngay.
**Trong lab:** dùng để tìm user theo username. Lab xử lý độ trễ bằng cách đọc lại theo `user_id`.

---

**Nhóm: Grant và token**

## Grant / Grant Types
Cách application đổi thông tin lấy token. Mỗi application chỉ dùng được những grant được bật trong *Advanced Settings → Grant Types*.
**Trong lab:** Web App bật Authorization Code và Password; M2M dùng Client Credentials.

## Authorization Code Flow
Luồng chuẩn: app redirect sang `/authorize`, Auth0 xử lý login rồi trả `code` về callback, sau đó **server** đổi `code` lấy token.
**Trong lab:** luồng **Sign in with Auth0**.

## PKCE (Proof Key for Code Exchange)
App tạo `code_verifier` bí mật và gửi `code_challenge` (SHA-256) lúc `/authorize`. Khi đổi code, app phải gửi đúng verifier, nên `code` bị đánh cắp không dùng được.
**Trong lab:** dùng S256; verifier được lưu trong cookie transaction.

## State
Giá trị ngẫu nhiên gửi đi lúc `/authorize` và kiểm tra lại ở callback, chống CSRF hoặc callback giả.
**Trong lab:** sai, thiếu hoặc hết hạn thì chuyển về `/?error=state`.

## Nonce
Giá trị ngẫu nhiên được Auth0 đưa vào ID token, chống dùng lại ID token cũ.
**Trong lab:** callback so khớp `nonce` trong ID token với transaction.

## ROPG (Resource Owner Password Grant)
Grant `password`: app gửi trực tiếp username/password tới `/oauth/token`. Chỉ dành cho app first-party được tin cậy.
**Trong lab:** dùng dưới dạng Password Realm.

## Password Realm Grant
Biến thể của ROPG, grant `http://auth0.com/oauth/grant-type/password-realm`, có thêm tham số **`realm`** để chọn connection. Trên Dashboard, nó được bật bằng ô **Password**. Nếu thiếu, Auth0 trả `unauthorized_client`.
**Trong lab:** luồng form login trong app (`/api/auth/login`).

## Client Credentials Grant
Grant cho M2M: gửi Client ID/Client Secret và audience để lấy access token, không có user.
**Trong lab:** lấy token Management API và cache tới gần lúc hết hạn.

## ID Token
JWT chứa danh tính user (`sub`, `name`...), dành cho **app**. Phải kiểm tra chữ ký qua JWKS cùng `iss`, `aud`, `exp`, `nonce` và `azp`.
**Trong lab:** không chứa connection, nên app phải tra thêm qua Management API.

## Access Token
Token để gọi API. Nếu không truyền `audience`, token chỉ dùng được cho `/userinfo`.
**Trong lab:** lưu trong cookie session HttpOnly; trang `/home` dùng nó để gọi `/userinfo`.

## Audience
Định danh API mà access token hướng tới, ví dụ `https://<tenant>/api/v2/` cho Management API, hoặc API riêng tạo trong *Applications → APIs*.
**Trong lab:** dùng cho token M2M; luồng login của user không truyền audience.

## JWKS
Tập public key của tenant tại `https://<tenant>/.well-known/jwks.json`, dùng để kiểm tra chữ ký RS256 của token.
**Trong lab:** thư viện `jose` tải và cache tự động.

## `azp` (Authorized Party)
Claim cho biết application nào nhận token. Cần kiểm tra khi `aud` có nhiều giá trị.
**Trong lab:** nếu có, `azp` phải bằng `AUTH0_CLIENT_ID`.

## `/userinfo`
Endpoint trả profile user khi gọi bằng access token.
**Trong lab:** dùng để chứng minh access token còn hợp lệ trên `/home`.

---

**Nhóm: Trang login và session**

## Universal Login
Trang login do Auth0 host. App chỉ redirect sang Auth0 rồi nhận kết quả; password không đi qua app.
**Trong lab:** nút **Sign in with Auth0**.

## Classic Login
Phiên bản cũ của Universal Login, cho phép thay toàn bộ HTML/JS. Auth0 không còn phát triển phiên bản này.
**Trong lab:** cách dùng để tự làm giao diện login hỗ trợ 2 connection.

## New Universal Login / Advanced Customizations
Phiên bản hiện tại của Universal Login. Giao diện tùy chỉnh bằng template, ACUL hoặc Page Templates, không thay toàn bộ JS.
**Trong lab:** chưa dùng; đây là hướng đi lâu dài Auth0 khuyến nghị.

## Custom Login Page
HTML dán ở *Branding → Universal Login → Advanced Options → Login → Customize Login Page* (Classic).
**Trong lab:** file `auth0-login-page.inline.html`.

## `@@config@@`
Chuỗi giữ chỗ trong Custom Login Page. Khi trả trang cho user, Auth0 thay bằng config của giao dịch login (base64), gồm domain, clientID, callbackURL, state, `_csrf`...
**Trong lab:** giữ nguyên; trang decode chuỗi này để tạo `WebAuth`.

## auth0.js / `WebAuth`
SDK JavaScript chạy trên trình duyệt. `new auth0.WebAuth(...)` rồi `.login({ realm, username, password })`.
**Trong lab:** tải từ CDN (`10.0.0`, có SRI) trong trang login.

## Lock
Widget login dựng sẵn của Auth0, khó thay đổi hành vi.
**Trong lab:** không dùng, vì cần tự chọn `realm`.

## Cross-Origin Authentication (`/co/authenticate`)
Endpoint mà `webAuth.login()` gọi để kiểm tra password từ trình duyệt. Endpoint này dùng cookie bên thứ ba khi trang khác domain tenant.
**Trong lab:** trang chạy trên domain tenant nên không gặp vấn đề third-party cookie.

## SSO Session (Auth0 session)
Cookie đăng nhập trên domain Auth0, khác với session của app. Khi còn session này, `/authorize` có thể đăng nhập lại ngay mà không hỏi password.
**Trong lab:** logout gọi thêm `/v2/logout` để xóa session này.

## `/v2/logout`
Endpoint xóa SSO session rồi redirect về `returnTo`. URL `returnTo` phải nằm trong Allowed Logout URLs.

---

**Nhóm: Mật khẩu và email**

## `/dbconnections/change_password`
Endpoint của Authentication API yêu cầu Auth0 gửi email đổi mật khẩu. **Bắt buộc có `email` và `connection`**. Auth0 vẫn trả 200 kể cả khi không tìm thấy user.
**Trong lab:** endpoint `/api/auth/forgot-password` gọi API này sau khi tìm ra email và connection.

## Password Reset Page / `Auth0ChangePassword`
Trang Classic mà link trong email mở ra. Trang dùng widget `Auth0ChangePassword` cùng các biến Liquid `{{email}}`, `{{ticket}}`, `{{csrf_token}}`, `{{password_policy}}`.
**Trong lab:** file `auth0-password-reset-page.html`.

## Password Change Ticket
URL đổi mật khẩu dùng một lần, chứa trong email hoặc tạo bằng Management API (`create:user_tickets`). Nếu tạo bằng API, app phải tự xác minh chủ tài khoản.
**Trong lab:** không tạo bằng API, vì như vậy sẽ bỏ qua bước xác minh qua email.

## Liquid
Ngôn ngữ template Auth0 dùng để render trang Password Reset và email (`{{ ... }}`).
**Trong lab:** không viết `{{` trong comment của trang reset.

## Email Templates / Redirect To
Mẫu email do Auth0 gửi, ví dụ Change Password hoặc Verification. **Redirect To** quyết định nơi user quay về sau khi đổi mật khẩu.

## Email Provider
Dịch vụ gửi email của tenant. Provider mặc định chỉ dùng để thử và có giới hạn; production nên dùng SMTP, SendGrid...

---

**Nhóm: Bảo vệ, mở rộng và vận hành**

## Attack Protection / Brute-force Protection
Cơ chế chặn đăng nhập sai nhiều lần theo user và IP.
**Trong lab:** đây là lý do không thử login lần lượt từng connection.

## Bot Detection / Captcha
Captcha Auth0 yêu cầu khi nghi ngờ bot. Custom page hiển thị bằng `webAuth.renderCaptcha()`.

## Actions
Code chạy ở các điểm trong luồng Auth0, ví dụ sau login hoặc trước khi tạo user, để thêm claim, chặn login...
**Trong lab:** không dùng. Lưu ý Actions cần redirect sẽ không chạy được với Password Realm.

## MFA
Xác thực nhiều lớp. Password Realm trả `mfa_required` khi bật MFA.
**Trong lab:** không hỗ trợ.

## Organizations
Tính năng B2B, nhóm user theo tổ chức.
**Trong lab:** không dùng.

## Logs (Monitoring → Logs) / event type
Nhật ký mọi sự kiện của tenant. Mỗi sự kiện có mã loại, ví dụ `fcpr` (Failed Change Password Request).
**Trong lab:** đây là nơi thấy lỗi thật khi API chỉ trả 200.

## Auth0 MCP Server
Gói `@auth0/auth0-mcp-server` (beta), cho phép AI client đọc hoặc sửa tenant qua Management API sau khi đăng nhập bằng device flow.
**Trong lab:** cấu hình `--read-only` trong `.vscode/mcp.json`.

