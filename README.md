# Next.js + Auth0: hai DB, một form login

Lab dùng **Auth0 (thuộc Okta)**, một tenant với hai Database Connections `devdb` và `ecomdb`. Không phải Okta Workforce `/api/v1/authn` và không cần tạo hai database SQL trong Next.js.

## Luồng xử lý

```text
Browser: username + password (không nhận email)
  -> POST /api/auth/login (Next.js server)
  -> POST Auth0 /oauth/token (client_credentials của M2M, cache đến gần hết hạn)
  -> GET Auth0 /api/v2/users?q=username:"..."&search_engine=v3
  -> Lọc identities: provider=auth0, connection=devdb hoặc ecomdb
  -> Yêu cầu đúng một database identity
  -> POST Auth0 /oauth/token
       grant_type=http://auth0.com/oauth/grant-type/password-realm
       realm=<connection vừa tìm được>
       username=<input>, password=<input>
  -> Kiểm tra chữ ký RS256 của ID token qua JWKS, issuer, audience, exp, sub
  -> Lưu profile đã xác thực vào encrypted HttpOnly cookie
  -> /home hiển thị user và connection
```

Management API **không kiểm tra password**. Chỉ Password Realm Grant xác thực thông tin đăng nhập. User không chọn DB; app không thử password lần lượt trên hai DB. Không có endpoint công khai để kiểm tra user tồn tại.

Giả định username duy nhất giữa hai connections. Không tìm thấy, sai password, hoặc tìm thấy nhiều identities đều trả lỗi đăng nhập chung. Linked accounts có nhiều database identities cũng bị từ chối thay vì chọn tùy ý.

### Tạo tài khoản

Mở **`/signup`** hoặc bấm **Create an account** trên trang login:

```text
Username + email + password + chọn devdb/ecomdb
  -> POST /api/auth/signup
  -> Kiểm tra Origin, input, rate limit và connection allowlist
  -> Management API tìm username trong cả hai DB để phát hiện trùng
  -> POST Auth0 /api/v2/users { username, email, password, connection }
  -> HTTP 201, hiển thị Account created + link về login
```

**Email bắt buộc khi signup nhưng chỉ dùng cho quên mật khẩu**; đăng nhập vẫn bằng username. Không tự đăng nhập sau signup. Chọn DB chỉ có ở signup; login vẫn tự tìm connection. User tạo trước khi có trường email cần được bổ sung email trên Auth0 Dashboard (Users → user → Edit email) thì mới dùng được quên mật khẩu.

Quy tắc username của lab: **1-128 ký tự**, chữ ASCII/số/`.`/`_`/`-`, tự trim và lowercase. Email và ký tự `@` bị từ chối. Password không trim, signup tối thiểu 8 ký tự; chính sách password/độ dài username trên từng Auth0 connection vẫn được áp dụng. Auth0 thường mặc định username tối đa 15 ký tự: chỉnh giới hạn trong connection nếu muốn dài hơn.

## 1. Cấu hình Auth0

### Regular Web Application (đăng nhập)

1. **Applications > Applications > Create Application > Regular Web Applications**.
2. Ghi lại Domain, Client ID, Client Secret vào các biến `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`.
3. **Advanced Settings > Grant Types**: bật **Password** và **Password Realm** nếu giao diện tách riêng. Grant cần có là `http://auth0.com/oauth/grant-type/password-realm`.
4. Dùng token endpoint authentication method **Post** (`client_secret_post`) và ID token signing algorithm **RS256**.
5. **Authentication > Database > devdb/ecomdb > Applications**: bật cùng Regular Web Application ở **cả hai** connections.
6. Nếu Dashboard yêu cầu callback URL, thêm `http://localhost:3000`. Flow này không dùng redirect callback, không cần tạo route callback, và không dùng Default Directory vì gửi `realm` tường minh.
7. Cấu hình username login/signup cho cả hai connections như bên dưới. Các user cũ chỉ có email cần được bổ sung username trong Auth0 trước khi dùng app này.
8. Dùng tài khoản lab không yêu cầu MFA, Organizations hoặc Actions cần redirect. Lab không xử lý các bước tương tác này; không tắt bảo vệ của tenant production để chạy lab.

### Database Connections: đăng nhập bằng username, có email để khôi phục

Trong **Authentication > Database > devdb/ecomdb > Attributes**:

1. Thêm/bật **Username**: cho phép dùng làm login identifier, đặt **Allow Signup with Username = Required**.
2. Giữ **Email** là attribute của connection (app luôn gửi email khi tạo user). Auth0 cần email để gửi link đổi mật khẩu.
3. Kiểm tra Password Realm Grant và Universal Login với user vừa tạo bằng **username**.

### Machine to Machine Application (tìm và tạo user)

1. Tạo application loại **Machine to Machine** riêng.
2. Authorize application cho **Auth0 Management API**, cấp **`read:users` và `create:users`** (không cần `update:users` hay `delete:users`).
3. Dùng token endpoint authentication method **Post**.
4. Điền Client ID/Secret vào `AUTH0_MANAGEMENT_CLIENT_ID`, `AUTH0_MANAGEMENT_CLIENT_SECRET`.
5. Audience do server tạo: `https://<AUTH0_DOMAIN>/api/v2/`. Lab dùng tenant domain chuẩn cho tất cả API/issuer; không trộn custom domain và tenant domain.
6. Cho phép M2M application thao tác trên cả hai connections qua Applications/`enabled_clients` nếu cấu hình tenant yêu cầu. Sau khi bổ sung scope hoặc thay credentials, restart Next.js để bỏ Management token đã cache.

Không dùng access token lấy thủ công từ API Explorer. Không đưa secrets vào biến `NEXT_PUBLIC_*`.

## 2. Chạy local

Yêu cầu Node.js >= 20.9 (khuyến nghị Node 22 LTS), npm.

```bash
npm install
cp .env.example .env.local
openssl rand -hex 32
```

Nếu npm 10 gặp lỗi resolver `Cannot read properties of null (reading 'edgesOut')`, dùng Node 22 LTS và `npx --yes npm@11 install` (không dùng `--force` hay bỏ kiểm tra TLS).

Điền các giá trị thật vào `.env.local`, dùng chuỗi ngẫu nhiên vừa tạo cho `SESSION_SECRET` (ít nhất 32 ký tự). File này được gitignore. Không gửi secrets qua chat.

```bash
npm run dev
```

Mở **http://localhost:3000**. `APP_ORIGIN` phải khớp chính xác origin trên trình duyệt; nếu đổi port/hostname thì sửa biến tương ứng, không thêm dấu `/` cuối. Restart server sau khi sửa env.

Thiếu config: trang chủ hiển thị Setup required và tên biến cần điền. Khi chạy production (`npm run build && npm start`), bắt buộc `APP_ORIGIN=https://...` và truy cập qua HTTPS reverse proxy vì cookie có cờ Secure.

## 3. Kiểm tra với tenant thật

| Trường hợp | Kết quả |
|---|---|
| Signup username mới, chọn devdb | Tạo user không email trong `devdb` |
| Signup username mới khác, chọn ecomdb | Tạo user không email trong `ecomdb` |
| Username của devdb + password đúng | Dashboard hiển thị `devdb` |
| Username của ecomdb + password đúng | Dashboard hiển thị `ecomdb` |
| Nhập email khi login/signup | Bị từ chối trước khi gọi Auth0 |
| Signup username đã tìm thấy trong một trong hai DB | HTTP 409, không tạo thêm |
| Password không đạt policy / connection vẫn yêu cầu email | Lỗi signup 400, không báo thành công |
| Client gửi connection khác hai DB cho phép | HTTP 400 |
| Sai password / user không tồn tại | Lỗi chung, không tạo session |
| Username trùng giữa hai DB (nếu có) | Lỗi chung, không thử password |
| User ở connection thứ ba | Không đăng nhập |
| Chưa login truy cập `/home` | Chuyển về `/` |
| Sign out, rồi truy cập lại dashboard | Chuyển về `/` |
| Hết hạn session / cookie bị sửa | Không truy cập được dashboard |
| 11 lần thử một username trong 5 phút | HTTP 429 (login/signup có bộ đếm riêng) |

```bash
npm test
npm run lint
npm run typecheck
npm run build
```

Test tự động dùng Auth0 response giả lập, không gọi tenant thật. Chúng không thay thế kiểm tra grant, connection enablement và credentials trên Auth0 của bạn.

## 4. Trang login host trên Auth0 (Custom Login Page)

Thư mục [hosted-pages/](hosted-pages/) build ra **một file JS** có cùng giao diện với trang login của lab, để upload lên Google Cloud Storage và nhúng vào **Custom Login Page** của Auth0 (Classic Login, template "Custom Login Form").

```text
Auth0 /authorize → Custom Login Page (HTML trên Auth0 + hosted-login.js từ GCS)
  -> User nhập username + password
  -> POST <lab app>/api/auth/resolve-connection { username }   (CORS chỉ cho domain Auth0)
       server dùng Management API tìm devdb/ecomdb, trả { connection }
  -> auth0.js webAuth.login({ realm: connection, username, password, captcha })
  -> Auth0 redirect về callback của application đã gọi /authorize
```

Trang chạy trên domain Auth0 nên **không giữ secret**; việc tìm DB phải do Next.js server làm.

### Build và upload

```bash
npm run build:hosted
# -> hosted-pages/dist/auth0-login-page.inline.html  (HTML hoàn chỉnh, JS nhúng sẵn: copy dán thẳng vào Auth0)
# -> hosted-pages/dist/hosted-login.<hash>.js và manifest.json (dùng khi host JS trên bucket)
```

**Cách nhanh (không cần bucket):** mở `hosted-pages/dist/auth0-login-page.inline.html`, copy toàn bộ, dán vào editor Custom Login Page của Auth0. Kiểm tra `EDIT 2` (`resolveUrl`) và `EDIT 3` (`signupUrl`).

Khi app đã deploy (ví dụ Cloud Run), build với origin thật để mọi URL trong trang trỏ đúng app:

```bash
HOSTED_APP_ORIGIN=https://<your-service>.run.app npm run build:hosted
```

**Cách dùng bucket:**

```bash
gcloud storage cp hosted-pages/dist/hosted-login.<hash>.js gs://YOUR_BUCKET/auth0/ \
  --content-type=application/javascript \
  --cache-control="public, max-age=31536000, immutable"
```

Object phải đọc công khai được (ví dụ `allUsers` có quyền `roles/storage.objectViewer` trên bucket/prefix). Mỗi lần sửa, build lại để có tên file mới thay vì ghi đè, tránh cache cũ.

### Cấu hình Auth0

1. **Branding → Universal Login → Advanced Options → Login**: bật **Customize Login Page**.
2. Dán nội dung [hosted-pages/auth0-login-page.html](hosted-pages/auth0-login-page.html), sửa 3 chỗ `EDIT`: URL file trên GCS, `resolveUrl`, `signupUrl`. **Giữ nguyên `@@config@@`.**
3. Save, rồi thử bằng **Authentication → Database → devdb/ecomdb → Try Connection**, hoặc từ application gọi `/authorize`.

### Lưu ý

- `resolveUrl` phải truy cập được từ **trình duyệt người dùng**. Với `http://localhost:5173`, Chrome có thể hỏi quyền **truy cập mạng cục bộ** (Local Network Access) vì trang Auth0 public gọi vào localhost; endpoint đã trả header preflight cần thiết. Khi deploy, dùng URL HTTPS public.
- CORS mặc định chỉ cho `https://<AUTH0_DOMAIN>`. Dùng custom domain thì khai báo `AUTH0_LOGIN_PAGE_ORIGINS`.
- **`/api/auth/resolve-connection` cho biết username có tồn tại hay không** (user enumeration). Chấp nhận được cho lab; endpoint có rate limit in-memory nhưng production cần thiết kế khác (ví dụ một connection duy nhất, hoặc Auth0 Actions/custom DB).
- Lỗi đăng nhập hiển thị thông báo chung, không hiển thị mô tả gốc của Auth0; password được xóa sau mỗi lần thất bại. Hỗ trợ Bot Detection captcha qua `webAuth.renderCaptcha`.
- Auth0 cho biết Classic Login không còn được phát triển thêm; hướng khuyến nghị lâu dài là Advanced Customizations for Universal Login.

## 5. Đăng nhập qua Auth0 (Universal Login) → trang Home

Nút **Sign in with Auth0** trên trang `/` để **Auth0 xử lý toàn bộ phần đăng nhập**; app không nhận password, chỉ nhận token. Form cũ (Password Realm Grant) vẫn giữ bên dưới để so sánh.

```text
/auth/login   tạo state + nonce + PKCE verifier (cookie tạm, mã hóa, 10 phút)
  -> Auth0 /authorize → Custom Login Page (mục 4) tìm devdb/ecomdb và đăng nhập
  -> Auth0 redirect /auth/callback?code=...&state=...
/auth/callback kiểm tra state → đổi code lấy token ở SERVER (client secret + code_verifier)
  -> verify ID token (RS256/JWKS, issuer, audience, nonce, exp)
  -> Management API: user thuộc đúng 1 connection devdb/ecomdb
  -> lưu profile + access token vào cookie session HttpOnly mã hóa → /home
/home         hiển thị user, connection, hạn token; server gọi Auth0 /userinfo bằng access token
Sign out      xóa session app + redirect Auth0 /v2/logout (xóa luôn phiên đăng nhập trên Auth0)
```

**Vì sao cookie thay vì localStorage:** token đổi ở server và nằm trong cookie HttpOnly nên JavaScript trên trình duyệt (kể cả script XSS) không đọc được. Lưu localStorage buộc app thành SPA giữ token ở trình duyệt.

### Cấu hình Auth0 cho Regular Web App (`AUTH0_CLIENT_ID`)

- **Allowed Callback URLs**: `http://localhost:5173/auth/callback` (= `APP_ORIGIN` + `/auth/callback`).
- **Allowed Logout URLs**: `http://localhost:5173` (= `APP_ORIGIN`).
- **Grant Types**: bật **Authorization Code** (giữ **Password** nếu còn dùng form cũ).
- **Application Login URI**: để trống khi chạy HTTP localhost (Auth0 yêu cầu HTTPS cho trường này).
- Cả hai connections `devdb`, `ecomdb` bật cho application này; M2M app vẫn cần `read:users`.
- Muốn dùng giao diện custom: cấu hình Custom Login Page ở mục 4. Nếu không, Auth0 hiển thị trang login mặc định (khi đó user phải chọn hoặc gõ đúng DB).

### Ghi chú

- `/auth/login` là GET; state + PKCE chống CSRF/giả mạo callback. Callback từ chối state sai, thiếu, hết hạn hoặc mở ở trình duyệt khác.
- Access token mặc định (không có `audience`) chỉ dùng được cho Auth0 `/userinfo`. Muốn gọi API riêng, thêm API trong Auth0 và tham số `audience`.
- Session tối đa 1 giờ; app chưa xin refresh token. Hết hạn thì đăng nhập lại (Auth0 SSO có thể đăng nhập lại không cần nhập password).
- `/dashboard` cũ chuyển hướng sang `/home`.

## 7. Deploy lên Cloud Run

Cloud Storage bucket chỉ host file tĩnh; app cần server để giữ secret và gọi Management API, nên chạy trên **Cloud Run**. Bucket chỉ dùng (tùy chọn) cho `hosted-login.<hash>.js`.

- Biến thường trên service: `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_MANAGEMENT_CLIENT_ID`, `AUTH0_DEV_CONNECTION`, `AUTH0_ECOM_CONNECTION`, `APP_ORIGIN=https://<service-url>`.
- Secret (Secret Manager, gắn bằng `--update-secrets`): `AUTH0_CLIENT_SECRET`, `AUTH0_MANAGEMENT_CLIENT_SECRET`, `SESSION_SECRET`. Service account chạy Cloud Run cần `roles/secretmanager.secretAccessor` trên từng secret.
- `APP_ORIGIN` phải đúng URL người dùng mở. Cloud Run có thể có 2 URL (`...-<project-number>.<region>.run.app` và `...-<hash>-<region-code>.a.run.app`); chỉ URL khớp `APP_ORIGIN` login được.
- Auth0 Regular Web App: thêm `https://<service-url>/auth/callback` vào **Allowed Callback URLs**, `https://<service-url>` vào **Allowed Logout URLs**.
- Build lại trang login Auth0 với `HOSTED_APP_ORIGIN` (mục 4) rồi dán lại vào Auth0.
- Rate limit và reservation signup là in-memory theo instance; Cloud Run có thể chạy nhiều instance nên giới hạn không chia sẻ giữa chúng.

Nếu `gcloud` báo `CERTIFICATE_VERIFY_FAILED` sau proxy công ty, export CA tin cậy của macOS và đặt `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` cho phiên đó (không tắt kiểm tra SSL).

## 6. Quên mật khẩu (Auth0 xử lý)

```text
Trang login trên Auth0 → "Forgot your password?" → nhập username
  -> POST <lab app>/api/auth/forgot-password { username }      (CORS chỉ cho domain Auth0)
       server: Management API tìm user trong devdb/ecomdb → lấy email + connection
       server: POST Auth0 /dbconnections/change_password { client_id, email, connection }
       luôn trả cùng một thông báo, dù username có tồn tại hay không
  -> Auth0 gửi email "Change Password" có link (dùng 1 lần, có hạn)
  -> Link mở trang Password Reset của Auth0 (giao diện lab) → nhập mật khẩu mới
  -> Auth0 lưu mật khẩu; user quay lại đăng nhập bằng username
```

App không bao giờ nhận hay lưu mật khẩu mới, không hiển thị email cho người yêu cầu.

### Cấu hình

1. **Login page**: build lại và dán lại `hosted-pages/dist/auth0-login-page.inline.html` (có thêm `forgotPasswordUrl` ở `EDIT 2b`).
2. **Password Reset page**: **Branding → Universal Login → Advanced Options → Password Reset**, bật **Customize Password Reset Page**, dán `hosted-pages/dist/auth0-password-reset-page.html`, Save. Trang dùng widget chính thức `Auth0ChangePassword` 1.5.6 (có SRI); giữ nguyên các biến `{{email}}`, `{{ticket}}`, `{{csrf_token}}`, `{{password_policy}}`.
3. **Email**: tenant cần gửi được email. Provider mặc định của Auth0 chỉ để thử và có giới hạn; cấu hình **Branding → Email Provider** (SendGrid, SMTP...) nếu cần ổn định. Template **Change Password** ở **Branding → Email Templates**; có thể đặt **Redirect To** = `http://localhost:5173` để sau khi đổi mật khẩu quay về lab.
4. User phải có email trên Auth0. User không có email: endpoint vẫn trả thông báo chung nhưng không có email nào được gửi (log server ghi `no_email`).

### Giới hạn

- Rate limit riêng: 3 yêu cầu/username/15 phút, 20 yêu cầu/phút toàn app (in-memory).
- Thông báo chung chống dò username qua nội dung phản hồi, nhưng thời gian phản hồi vẫn có thể khác nhau; `/resolve-connection` vẫn tiết lộ username tồn tại (xem mục 4).
- Ai biết username có thể khiến Auth0 gửi email reset tới chủ tài khoản (không đổi được mật khẩu nếu không có quyền vào hộp thư). Đây là hành vi chuẩn của luồng quên mật khẩu.

## Giới hạn và bảo mật

- **Username search chỉ dành cho lab**: `/users` search **eventually consistent**, Auth0 không khuyến nghị dùng endpoint này trong authentication path. User mới tạo/đổi username có thể chưa tìm được ngay; đợi rồi thử login lại, không đăng ký lại. Lab đối chiếu username đã lowercase và từ chối khi kết quả chạm giới hạn 100; không tự chọn kết quả đầu.
- Signup kiểm tra trùng qua search và giữ reservation trong bộ nhớ 10 phút để chặn tạo cùng username đồng thời hoặc ngay sau signup trong một process. Nếu request tạo user timeout, reservation được giữ vì Auth0 có thể đã tạo xong. **Không bảo đảm uniqueness xuyên hai DB** sau restart, giữa nhiều instances, user tạo ngoài app hoặc khi index trễ quá thời gian này. Cần registry duy nhất/khóa phân tán bền vững cho production; login luôn từ chối khi tìm thấy trùng.
- **Trang signup công khai và cho chọn cả devdb chỉ dành cho lab**. Không dùng database selection làm phân quyền. Management API tạo user theo quyền M2M, không được giả định nó chạy cùng các signup protections/Actions như Universal Login. Không mở endpoint này public trên tenant thật có dev access; production cần kiểm soát admin/invitation và chống bot phù hợp.
- ROPG/password-realm dành cho app first-party được tin cậy. App xử lý password ở server nên **không phù hợp thay thế Universal Login cho production** có MFA/SSO/passkeys. Browser chỉ gọi Next.js cùng origin.
- Mọi token/secret chỉ ở server; không trả token Auth0 về UI, không lưu password, không log username/password/token hoặc response body từ Auth0.
- Cookie được mã hóa/xác thực bằng iron-session, HttpOnly, SameSite=Lax, Secure trong production. Chỉ lưu profile; thời hạn tối đa một giờ và không vượt quá `exp` của ID token. Trang được bảo vệ kiểm tra hạn mỗi request.
- Logout chỉ xóa session hiện tại của app. Cookie stateless không có cơ chế thu hồi tập trung; nếu user bị khóa/xóa ở Auth0 sau login, session cũ vẫn có thể dùng đến khi hết hạn. Đổi `SESSION_SECRET` làm mất hiệu lực toàn bộ cookie.
- Login/signup/logout kiểm tra Origin để chống CSRF; input giới hạn độ dài và body tối đa 8 KB; request Auth0 timeout 10 giây; lookup escape Lucene và đối chiếu exact.
- Rate limit in-memory: login và signup mỗi loại 10 lần/username/5 phút và 60 lần/process/phút; không tin `X-Forwarded-For` từ client. Limiter reset khi restart và không chia sẻ giữa instances. Cần shared limiter/gateway + giới hạn thời gian nhận body trước khi deploy public.
- Giữ Auth0 Attack Protection. ROPG từ backend có hạn chế về client IP/bot protection; lab không tự forward IP header không được tin cậy. Tham khảo tài liệu bên dưới khi deploy.
- Lỗi không có user/sai password dùng cùng message nhưng **không bảo đảm chống timing enumeration** (lookup không thấy user sẽ không gọi login).
- Connection hiển thị sau login chỉ là thông tin lab, **không tự cấp role/admin permission**.

## Troubleshooting

- **503**: kiểm tra domain, credentials M2M, scope `read:users`/`create:users`, token endpoint auth method, grant types, connection enabled, RS256, rate limits Auth0 và mạng. Với signup, có thể request đã tạo user nhưng response bị mất: kiểm tra Auth0/thử login trước khi tạo lại. Log chỉ ghi endpoint/status hoặc loại lỗi an toàn.
- **400 signup**: kiểm tra username length, password policy, connection có cho phép không email hay không. App không chuyển nguyên response của Auth0 về browser.
  - `connection_disabled` (Auth0: "The connection is disabled"): connection chưa bật cho application. Vào **Authentication > Database > devdb/ecomdb > Applications**, bật **cả M2M app** (tạo user) **và Regular Web App** (login) trên cả hai connections.
  - `email_required`: Auth0 báo thiếu email bắt buộc; cấu hình connection chưa hỗ trợ request signup không email. Chỉ bật Require Username không giải quyết yêu cầu email.
  - `username_not_enabled`: Auth0 báo không cho dùng username; bật Username attribute cho connection đã chọn.
  - `password_policy`: Auth0 báo lỗi chính sách password; dùng password đáp ứng policy của connection.
  - `signup_rejected`: lỗi validation chưa nhận diện được; không tự kết luận là lỗi email/password. Kiểm tra cấu hình connection và sự kiện tương ứng trong Auth0 Dashboard.
  - Log request bị từ chối ghi endpoint, method, HTTP status và mã nguyên nhân an toàn trong một chuỗi, tránh trường hợp Next.js ghi object thành `{}`. Response browser có `code` tương ứng; không chứa raw response, username, password hoặc token từ Auth0.
  - Khi chạy **local (không phải production)**, log signup 400 có thêm trường `detail`: mô tả lỗi của Auth0 (tối đa 300 ký tự), đã thay username/password bằng `[redacted]`. Lỗi Management API 400 có thể không xuất hiện trong biểu đồ Signups của Dashboard, nên dùng `detail` này để chẩn đoán.
- **409 signup**: username đã tồn tại hoặc đang trong reservation. Dùng username khác, hoặc thử login nếu vừa tạo tài khoản.
- **401**: kiểm tra password, username đã cấu hình (không phải email), độ trễ search index, DB được cho phép, tài khoản bị block hoặc Auth0 Action từ chối login.
- **403 từ `oauth/token`** (log có `grant` và `error`): `unauthorized_client` với `grant` là `password-realm` nghĩa là Regular Web App chưa bật grant **Password** (Advanced Settings > Grant Types); với `grant` là `client_credentials` nghĩa là M2M app chưa được authorize cho Management API. Khi chạy local, `detail` chứa mô tả lỗi của Auth0 đã che username/password/client secret.
- **MFA required**: lab không xử lý MFA; dùng tài khoản lab thích hợp hoặc đổi thiết kế sang Universal Login.
- **403 Request origin**: `APP_ORIGIN` không trùng origin browser, hoặc client không gửi Origin.
- Không dùng tùy chọn tắt TLS verification nếu gặp lỗi CA trong môi trường corporate; cấu hình CA tin cậy/system CA cho Node.

## Tài liệu

- [Password Realm Grant](https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow/call-your-api-using-resource-owner-password-flow)
- [Username configuration](https://auth0.com/docs/authenticate/database-connections/require-username)
- [Flexible Identifiers và giới hạn](https://auth0.com/docs/authenticate/database-connections/flexible-identifiers-and-attributes)
- [Management API: Create a User](https://auth0.com/docs/api/management/v2/users/post-users)
- [User search và giới hạn consistency](https://auth0.com/docs/manage-users/user-search/list-and-search-users)
- [ROPG và Attack Protection](https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow/avoid-common-issues-with-resource-owner-password-flow-and-attack-protection)

Code chính: [Auth0 client](src/lib/auth0.ts), [login route](src/app/api/auth/login/route.ts), [signup route](src/app/api/auth/signup/route.ts), [signup form](src/components/signup-form.tsx), [session](src/lib/session.ts), [login form](src/components/login-form.tsx).
