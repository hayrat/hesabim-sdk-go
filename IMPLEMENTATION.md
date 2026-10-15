# Go Backend'ini Hayrat Hesabım'a Bağlama

> Bu doküman bir Go backend'ine "Hesabım ile giriş" ve yetki kontrolü eklemek
> için gereken her şeyi içerir. Hedef: bir mühendise **ya da bir AI kod
> ajanına** "bu projeyi `hesabim-sdk-go`'nun `IMPLEMENTATION.md`'sine göre
> entegre et" denildiğinde, başka bir yere bakmadan ve soru sormadan işin
> bitmesi.
>
> Tarayıcı tarafı (SPA) için eş doküman:
> [`hesabim-sdk-js` → IMPLEMENTATION.md](https://github.com/hayrat/hesabim-sdk-js/blob/main/IMPLEMENTATION.md).

---

## 0. AI ajanı için talimat — önce bunu oku

Bu bölüm bir iş listesidir; sırayla uygula.

1. **Topolojiyi belirle (§2).** Hedef projeye bak:
   - Tarayıcıda çalışan ayrı bir SPA var (Vue/React/Svelte…) ve backend yalnızca
     JSON API sunuyorsa → **Topoloji A** (SPA + Go API).
   - Backend HTML render ediyorsa, sunucu tarafı oturum/çerez kullanıyorsa ya
     da frontend'in token görmemesi isteniyorsa → **Topoloji B** (Go BFF).
   - Emin değilsen ve backend'de oturum altyapısı yoksa **A**'yı seç.
   Seçimini ve gerekçesini bitiş raporuna yaz.
2. **Değerleri uydurma.** `HESABIM_AUDIENCE`, `HESABIM_CLIENT_ID` gibi değerleri
   bilmiyorsan kodu **env'den okuyacak** şekilde yaz, yerel geliştirme için
   örnek dosyaya (`.env.example`, `docker-compose`, `config.example.yaml` —
   projede hangisi varsa) **placeholder** koy ve devam et. Durup sorma.
3. **Sırları asla repoya koyma.** `HESABIM_CLIENT_SECRET` yalnız ortam
   değişkeninden okunur; hiçbir dosyaya, teste, log satırına, hata mesajına
   yazılmaz. Placeholder bile gerçek bir değere benzemesin: `change-me`.
4. **Kopyala, icat etme.** Bu repodaki [`examples/`](examples/) altındaki
   programlar derlenen ve test edilen tam örneklerdir. Kendi framework'üne en
   yakın olanı al (§5.3, §6.1), projenin stiline uyarla. Header ayrıştırma,
   PKCE, refresh kilidi gibi şeyleri yeniden yazma.
5. **Kullanıcı tablosu.** Projede kullanıcı tablosu varsa `sub` (UUID) kolonu
   ekle ve kullanıcıyı onunla eşle; yoksa §9'daki projeksiyonu kur.
6. **Doğrula (§13)** — derleme, test, ve elle yapılacak uçtan uca kontrol.
7. **Bitiş raporu (§14)** — yöneticiden istenecek değerler ve kayıt talebi
   metni dahil.

---

## 1. Ne kazanıyorsun, ne yazıyorsun

Hesabım bir **OIDC kimlik sağlayıcısıdır** (Authorization Code + PKCE).
Issuer: `https://hesabim.hayrat.com`.

**Yazmadığın şeyler:** giriş ekranı, tek kullanımlık kod (OTP) akışı, e-posta /
SMS gönderimi, bot koruması, SSO oturumu, kullanıcı kayıt ve profil ekranları.

**Yazdığın şeyler:** API'nde bir doğrulama middleware'i, handler'larında
`Can(rol, hedef)` çağrıları, (BFF'te) login/callback/logout uçları ve
uygulamana özgü kullanıcı tablosu.

**Bedava gelen:** rol + veri kapsamı access token'ın içinde gelir.
"Ayşe, Ankara ilinde moderatör" bilgisi senin veritabanında durmaz.

```
  Tarayıcı                         Hesabım (IdP)                Senin Go API'n
     │ 1. login (Code + PKCE) ───────►│                               │
     │ ◄───── 2. ?code=…&state=… ─────│                               │
     │ 3. code → token ──────────────►│ /oauth/token                  │
     │ ◄─── access + refresh + id ────│                               │
     │ 4. Authorization: Bearer ──────┼──────────────────────────────►│
     │                                │◄──── /oauth/jwks (önbellekli) ─│ 5. SDK yerel doğrular
     │ ◄──────────────── veri ────────┼───────────────────────────────│
```

- Access token'ı **senin API'n yerel doğrular**: imza, issuer'ın JWKS'indeki
  public key ile kontrol edilir. Her istekte IdP'ye gidilmez.
- Topoloji A'da 1–3'ü tarayıcıdaki JS SDK yapar. Topoloji B'de 1–3'ü senin
  Go backend'in yapar ve tarayıcı token görmez.

---

## 2. Topoloji seçimi

| | **A — SPA + Go API** | **B — Go BFF** |
|---|---|---|
| Client tipi (kayıtta) | `public` | `confidential` |
| Token nerede | Tarayıcı (JS SDK yönetir) | Sunucuda; tarayıcıda yalnız HttpOnly çerez |
| `/oauth/token`'ı kim çağırır | Tarayıcı | Go backend |
| Client secret | Yok | Var — yalnız env'de |
| PKCE | Zorunlu | **Zorunlu** (confidential'da da) |
| Go tarafında yazılan | Middleware + `Can` + `/api/me/sync` | Login/callback/refresh/logout + middleware + `Can` |
| Kopyalanacak örnek | `examples/resource-server/<framework>` | `examples/bff` |
| XSS'te token çalınabilir mi | Evet (kısa ömürlü) | Hayır |

Client tipi kayıttan sonra **değiştirilemez**; yanlış seçilirse client silinip
yeniden açılır. Sunucu tarafı bir backend'in zaten varsa ve token'ın tarayıcıya
inmemesini istiyorsan B'yi seç.

---

## 3. Kayıt — Hesabım yöneticisine gönderilecek talep

Proje, client ve rol kaydını **Hesabım yöneticisi** yapar; entegre eden taraf
yapmaz. Aşağıdaki metni doldurup yöneticiye ilet (ajan: bunu bitiş raporuna
koy).

```text
Konu: Hesabım entegrasyonu — <Proje Adı>

Proje anahtarı (key): <ornek-proje>        # küçük harf + tire; sonradan DEĞİŞTİRİLEMEZ
Proje adı:            <Örnek Proje>
Client tipi:          public | confidential  # A → public, B → confidential
Client id önerisi:    <ornek-proje-spa | ornek-proje-bff>

redirect_uris (birebir eşleşir — sondaki /, port, http/https dahil):
  - https://<prod-alan-adı>/<callback-yolu>
  - <yerel geliştirme URI'si — aşağıdaki nota bak>

post_logout_redirect_uris:
  - https://<prod-alan-adı>/
  - <yerel geliştirme kökü>

Roller (uygulamanın kendi sözlüğü):
  - <admin>
  - <moderator>  — kapsamlı mı? (bölge / il / ilçe / okul) ya da proje geneli
  - …

Test kullanıcısı için atama: <kişi> → <rol> [<kapsam tipi> <kapsam>]
```

Callback yolları: Topoloji A'da SPA'nın callback sayfası (JS SDK dokümanı
`/auth/callback` kullanır), Topoloji B'de BFF'in `/auth/callback` ucu.

**Yerel geliştirme URI'si topolojiye göre farklıdır:**

| Topoloji | Client tipi | Yerel URI | Neden |
|---|---|---|---|
| A (SPA) | `public` | `https://localhost:<port>/auth/callback` | Canlı IdP, public client için `http://` redirect'i **reddeder** ve tarayıcı origin'i olarak yalnız `https` sayar. SPA'nın dev sunucusu HTTPS ile çalışmalı (JS SDK dokümanı tarif eder). |
| B (BFF) | `confidential` | `http://localhost:<port>/auth/callback` | Token isteğini sunucu attığı için CORS yok; confidential client'ta `http://localhost` kabul edilir. |

**Yöneticiden dönecek değerler:**

| Değer | Sır mı | Nereye |
|---|---|---|
| `client_id` | Hayır | `HESABIM_CLIENT_ID` (B) / frontend config (A) |
| Audience: `api:<proje-key>` | Hayır | `HESABIM_AUDIENCE` |
| Client secret (yalnız B) | **EVET** | Yalnız sunucu ortamının secret deposu → `HESABIM_CLIENT_SECRET` |

Client secret **tek seferlik gösterilir** ve yalnız güvenli bir kanaldan
(parola yöneticisi, secret deposu) iletilir. E-postaya, sohbete, issue'ya,
repoya yazılmaz. Kaybolursa yönetici yeni secret üretir (eskisi belirli bir
örtüşme süresinden sonra ölür; sızıntıda anında).

Kayıt sonrası tarayıcı origin'i (CORS) kayıtlı `redirect_uris`'ten otomatik
türetilir; ayrıca ayar yoktur, en geç ~1 dakikada etkinleşir. Canlı ortamda
yalnız `https` origin'leri sayılır.

---

## 4. Ortam değişkenleri

| Env | Topoloji | Zorunlu | Sır mı | Örnek / varsayılan |
|---|---|---|---|---|
| `HESABIM_ISSUER_URL` | A, B | Hayır | Hayır | `https://hesabim.hayrat.com` (varsayılan) |
| `HESABIM_AUDIENCE` | A, B | **Evet** | Hayır | `api:ornek-proje` |
| `HESABIM_CLIENT_ID` | B | **Evet** | Hayır | `ornek-proje-bff` |
| `HESABIM_CLIENT_SECRET` | B | **Evet** | **EVET** | — (commit'lenmez, loglanmaz) |
| `HESABIM_REDIRECT_URI` | B | **Evet** | Hayır | `https://ornek.hayrat.com/auth/callback` |
| `HESABIM_POST_LOGOUT_REDIRECT_URI` | B | **Evet** | Hayır | `https://ornek.hayrat.com/` |

Eksik zorunlu değişkende süreç **başlamaz** ve yalnız değişkenin **adını**
loglar (değerini değil).

---

## 5. Topoloji A — Go API (resource server)

### 5.1 Modülü ekle

```sh
go get github.com/hayrat/hesabim-sdk-go@latest
```

Go 1.26+. Tek bağımlılık `github.com/golang-jwt/jwt/v5`. Paket adı `hesabim`.

### 5.2 Doğrulayıcıyı başlangıçta kur

```go
verifier, err := hesabim.New(ctx, hesabim.Config{
    IssuerURL: envOr("HESABIM_ISSUER_URL", "https://hesabim.hayrat.com"),
    Audience:  os.Getenv("HESABIM_AUDIENCE"), // "api:<proje-key>", birebir
})
if err != nil {
    // Kasıtlı: New discovery + JWKS okur. Hiçbir token'ı doğrulayamayacak bir
    // servis "sağlıklı" görünerek ayakta kalmamalı.
    log.Fatalf("hesabim: %v", err)
}
```

`verifier` süreç başına **bir kez** kurulur ve paylaşılır (eşzamanlı kullanım
güvenli; JWKS'i kendisi tazeler).

### 5.3 Middleware — framework'üne göre örnek

| Framework | Kopyalanacak dosya | Bağlama |
|---|---|---|
| `net/http` (Go 1.22+ mux) | `examples/resource-server/nethttp/main.go` | `mux.Handle("/api/", verifier.Middleware(api))` |
| Echo v4 | `examples/resource-server/echo/main.go` | `e.Group("/api", echo.WrapMiddleware(verifier.Middleware))` |
| Gin | `examples/resource-server/gin/main.go` | `hesabimAuth(verifier)` adaptörünü **olduğu gibi** kopyala |
| chi | `examples/resource-server/chi/main.go` | `r.Use(verifier.Middleware)` |
| Diğer (gRPC vb.) | — | `verifier.Verify(ctx, rawToken)`; 401'de hata metnini istemciye **yazma** |

Middleware yalnız **401**'e karar verir (token yok / geçersiz / başka API'nin
token'ı). **403 senin handler'ının** kararıdır, çünkü hangi kaynağın
istendiğini yalnız handler bilir. `Authorization` header'ını kendin ayrıştırma.

### 5.4 Handler'da yetki

```go
func districtReports(w http.ResponseWriter, r *http.Request) {
    p, ok := hesabim.FromContext(r.Context())
    if !ok {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }
    id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
    if !p.Can("moderator", hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: id}) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // …
}
```

Kurallar §7'de. `p.Subject` kullanıcının kalıcı UUID'sidir (§9).

### 5.5 Kullanıcı projeksiyonu: `POST /api/me/sync`

Topoloji A'da backend yalnız **access token** görür ve access token'da ad
yoktur. Desen:

- JS SDK, kendi doğruladığı ID token'dan `getUser()` ile `name`/`gender` okur ve
  her girişten sonra bir kez `POST /api/me/sync` çağırır (bkz. JS SDK
  dokümanı).
- Gövde: `{"name": string|null, "gender": "male"|"female"|null}` (JS SDK
  `u.name ?? null` gönderir). `null` ya da eksik alan `""` olarak saklanır.
- Backend satırın **anahtarını** (`sub`) ve **`profile_ver`**'i
  **doğrulanmış access token'dan** (`hayrat_profile_ver` →
  `Principal.ProfileVersion`) alır; gövdedeki `name`/`gender` kullanıcının
  kendi tarayıcısının beyanıdır. Gövdede `sub` ya da `profile_ver` gelse bile
  yok sayılır → kişi yalnız **kendi** satırını yazabilir.
- `name`/`gender` yalnız **görüntüleme verisidir**; hiçbir yetki kararına
  girmez. Issuer tarafından imzalı profil gerekiyorsa Topoloji B kullan.

Hazır implementasyon: `examples/users/users.go` → `users.SyncHandler(store)`
(gövde doğrulama, 4 KB sınırı, `gender ∈ {"", "male", "female"}`), şema
`users.PostgresSchema`, `database/sql` ile upsert `users.SQLStore`.
`examples/resource-server/nethttp` bunu `/api/me/sync`'e bağlar.

### 5.6 Frontend

SPA tarafı: [`hesabim-sdk-js` → IMPLEMENTATION.md](https://github.com/hayrat/hesabim-sdk-js/blob/main/IMPLEMENTATION.md).
Özetle her API çağrısından önce `await hesabim.getAccessToken()` ve
`Authorization: Bearer <token>`.

### 5.7 SPA ile API aynı origin'de mi? — CORS kararı

- **Varsayılan (önerilen): aynı origin.** SPA ve API tek alan adından
  servis edilir; bir reverse proxy `/api`'yi bu servise yönlendirir
  (geliştirmede: Vite `server.proxy`). CORS yoktur, ayar yoktur.
- **Ayrı origin şartsa** (`app.example` → `api.example`): tarayıcı her
  `Authorization` header'lı istekten önce bir **preflight (`OPTIONS`)** atar ve
  preflight token **taşımaz**. Kurallar:
  1. CORS katmanı auth middleware'inin **dışında** (önünde) olur; aksi halde
     preflight 401 alır ve asıl istek hiç gitmez.
  2. Yalnız izin listesindeki origin'ler, **birebir** (wildcard yok, gelen
     origin'i körü körüne yansıtma yok).
  3. `OPTIONS` → `204`, auth'suz; `Access-Control-Allow-Headers` en az
     `Authorization, Content-Type`.
  4. Çerez gerekmediği için `Allow-Credentials` açılmaz.

  Hazır implementasyon: `examples/resource-server/nethttp/cors.go`
  (`withCORS`, testli). `CORS_ALLOWED_ORIGINS` env'i (virgülle ayrılmış tam
  origin listesi) boşsa kapalıdır. Echo/Gin/chi'de framework'ün kendi CORS
  middleware'i aynı kurallarla kullanılabilir — sıralama kuralı (1) aynıdır.

---

## 6. Topoloji B — Go BFF (confidential client)

### 6.1 Örneği taşı

`examples/bff/` tam bir BFF'tir; dosyaları projene taşı:

| Dosya | İçerik |
|---|---|
| `auth.go` | `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/me`, oturum → bearer token köprüsü, refresh |
| `session.go` | `Store` arayüzü, in-memory store, oturum başına kilit |
| `main.go` | env okuma, rotalar, CSRF koruması, örnek API handler'ları |
| `../users/users.go` | kullanıcı projeksiyonu |

Bağımlılıklar: `github.com/hayrat/hesabim-sdk-go`,
`github.com/coreos/go-oidc/v3` (discovery + ID token doğrulama),
`golang.org/x/oauth2` (code exchange, PKCE, refresh).

Projen Echo/Gin/chi kullanıyorsa: `/auth/*` handler'ları düz
`http.HandlerFunc`'tır, framework'ün `WrapHandler`/`gin.WrapF` karşılığıyla
bağla; `/api` grubunu `a.requireSession(a.api.Middleware(...))` zinciriyle sar
(Echo: `echo.WrapMiddleware`, Gin: §5.3'teki adaptör deseni).

### 6.2 Örneğin yaptıkları — değiştirme

- **Login:** `state`, `nonce` ve PKCE `code_verifier` üretir, üçünü **sunucu
  tarafı** bir "bekleyen giriş" kaydına yazar (çereze değil; tarayıcıda yalnız
  ayrı bir `hesabim_login` çerezinde kaydın opak id'si), `S256` challenge ile
  `/oauth/authorize`'a 302. `response_mode` göndermez (yalnız `query`
  desteklenir). `returnTo` yalnız site içi bir yol olabilir (açık yönlendirme
  koruması). **Mevcut oturuma dokunmaz:** başka bir sitenin linki
  `/auth/login`'e gelebilir, bu bir zorla-çıkış yolu olmamalı.
- **Callback:** `state`'i sabit zamanlı karşılaştırır, kodu
  `client_secret_basic` + `code_verifier` ile değiştirir, ID token'ı JWKS ile
  doğrular (imza ES256, `iss`, `exp`, `aud = client_id`) ve `nonce`'u kontrol
  eder; access token'ı da SDK ile doğrular (yanlış audience giriş anında
  yakalanır). Kullanıcı projeksiyonunu ID token'daki `name`/`gender` ile
  upsert eder (`profile_ver` doğrulanmış access token'dan). Tarayıcının önceki
oturumu varsa onu siler ve **yeni oturum id'si** verir (fixation koruması).
- **Çerez:** `hesabim_session`, `HttpOnly`, `SameSite=Lax`, redirect URI
  `https` ise `Secure`. İçinde yalnız opak oturum id'si var.
- **Refresh:** access token bitmesine 30 sn kala yeniler. **Rotasyon
  zorunlu:** her yenilemede yeni refresh token gelir ve eskisi ölür — yenisi
  hemen saklanır. Aynı refresh token'ı iki kez kullanmak **reuse detection**'ı
  tetikler ve tüm oturumu iptal eder; bu yüzden yenileme **oturum başına
  kilitlidir** ve kilit altında oturum yeniden okunur.
- **Refresh sonucuna göre davranış** — refresh token, IdP isteği **kabul
  ettiği anda** harcanır; harcanmış token'ı tekrar göndermek tüm oturumu iptal
  eder:

  | Sonuç | Davranış |
  |---|---|
  | İstek hiç gitmedi (DNS / bağlantı kurulamadı) | Token harcanmadı → işaret temizlenir, oturum **korunur**, `503 {"error":"auth_unavailable"}` |
  | İstek gitti ve cevap başarı **değil** — `invalid_grant`, başka herhangi bir 4xx, 5xx, zaman aşımı, kopan bağlantı | Token harcanmış olabilir → oturum **sonlandırılır**, `401 {"error":"login_required"}`; token **asla tekrar gönderilmez** |
  | Rotasyon başarılı ama yeni token'lar saklanamadı | Bir kez daha `Save`; yine olmazsa oturum sonlandırılır (saklı refresh token zaten ölü) |
  | Bu sırada logout / yeni giriş oldu | Sonuç **atılır**, oturum diriltilmez, `401` — ama çerez **silinmez** (artık yeni oturumun çerezi olabilir) |

  **`invalid_client` de oturumu bitirir.** Yanlış/rotasyonla değişmiş client
  secret böyle görünür: her kullanıcı bir sonraki yenilemede çıkış yapar ve
  log'da `the issuer refused this client (invalid_client) — check
  HESABIM_CLIENT_ID / HESABIM_CLIENT_SECRET` yazar. Bu kasıtlıdır: cevabın
  token'ı harcamadığı garanti edilemez, ve "tekrar dene" kuralı tek bir yanlış
  tahminde tüm oturumu iptal ettirir. Secret rotasyonunda örtüşme süresi
  (eski ve yeni secret birlikte geçerli) kullan.

  Tekrar göndermeyi **imkânsız** kılan iki kural (süreç çökse, lease düşse,
  silme başarısız olsa bile):

  1. **Kalıcı işaret:** token isteği gitmeden **önce** oturuma koşullu yazma
     ile `RefreshPending = true` (+ başlangıç zamanı) kaydedilir; yalnız
     saklanan bir sonuç onu temizler. Sonraki herhangi bir refresh girişimi
     işareti görürse token'ı göndermez, oturumu sonlandırır (`401`).
  2. **Koşullu (sürümlü) kayıt:** her oturum bir `Version` taşır;
     `Store.Save(ctx, s, ttl, expectedVersion)` yalnız saklı sürüm hâlâ
     `expectedVersion` ise yazar (`0` = yeni oturum, kayıt olmamalı), aksi
     halde `errConflict` döner ve hiçbir şey yazmaz. Refresh sonucu bu yüzden
     arada silinmiş (logout) ya da değişmiş bir oturumu geri getiremez.

  Refresh ve `Save`, isteğin context'inden **ayrılmış**
  (`context.WithoutCancel`) bir context'te, açık bir süre sınırıyla
  (`refreshBudget` = 10 sn; tek token isteği `tokenRequestTimeout` = 5 sn)
  koşar: tarayıcı istek ortasında giderse IdP'nin zaten yaptığı rotasyon
  yarıda bırakılmaz.
- **Oturum deposu hatası çıkış değildir:** depo (Redis) erişilemezse
  `503 {"error":"auth_unavailable"}` döner ve çerez **silinmez**. Yalnız
  "oturum yok" (`errNoSession`) `401` + çerez silme demektir.
- **API:** oturumdaki access token `Authorization: Bearer` olarak isteğe konur
  ve SDK middleware'inden geçer; handler'lar Topoloji A ile **aynıdır**
  (`hesabim.FromContext`, `p.Can`).
- **CSRF:** `http.NewCrossOriginProtection()` tüm rotaları sarar;
  çapraz kökenli POST/PUT/PATCH/DELETE reddedilir.
- **Logout:** `POST /auth/logout` yerel oturumu siler ve tarayıcıyı
  `end_session_endpoint`'e `id_token_hint` + `post_logout_redirect_uri` ile
  303'le gönderir. **Silme başarısızsa** başarılı gibi davranmaz:
  `503`, çerez korunur, kullanıcı tekrar dener. Aynı kural yeni girişte:
  tarayıcının önceki oturumu silinemezse yeni oturum kurulmaz (`503`).

### 6.3 Üretime geçerken

- **Birden fazla replika:** `Store`'u Redis ile implemente et (anahtar başına
  JSON, TTL = `Save`'in `ttl` argümanı). `Get`, anahtar yoksa `errNoSession`
  döner; bağlantı/zaman aşımı hatalarını **olduğu gibi** döndürür (handler'lar
  bunları 503'e çevirir — "oturum yok" ile karıştırma). In-memory store tek
  süreç içindir.
- **`Save` atomik ve koşullu olmalı** — sürüm kontrolü ile yazma **tek bir Lua
  betiğinde** (ayrı `GET` + `SET` yarışa açıktır, kullanma). Oturum JSON'u
  `sess:{<id>}`, sürümü `sessv:{<id>}` anahtarında — süslü parantez **hash
  tag**'dir, iki anahtarı Redis Cluster'da aynı slota koyar (yoksa betik ve
  çok anahtarlı `DEL` `CROSSSLOT` ile düşer):
  ```lua
  -- KEYS[1]=sess:{<id>}  KEYS[2]=sessv:{<id>}
  -- ARGV[1]=beklenen sürüm, ondalık STRING ("0" = yeni oturum)
  -- ARGV[2]=yeni JSON (Version alanı = beklenen+1)  ARGV[3]=TTL ms
  local cur = redis.call("GET", KEYS[2])
  if ARGV[1] == "0" then
    if cur then return 0 end
  elseif cur ~= ARGV[1] then          -- string karşılaştırma: Lua sayıları double'dır
    return 0
  end
  redis.call("INCR", KEYS[2])         -- int64, kesin; yoksa 1'den başlar
  redis.call("PEXPIRE", KEYS[2], ARGV[3])
  redis.call("SET", KEYS[1], ARGV[2], "PX", ARGV[3])
  return 1
  ```
  `0` → `errConflict`. Go tarafı beklenen sürümü `strconv.FormatInt` ile
  gönderir ve `expectedVersion == math.MaxInt64` ise betiği çağırmadan
  `errConflict` döner (sürüm asla sarmaz; `INCR` o noktada zaten hata verir).
  `Delete`: `DEL sess:{<id>} sessv:{<id>}` (aynı slot, tek komut).
- **Dağıtık refresh kilidi** — `sessionLocks`'un yerine, aynı kurallarla:
  1. **Al:** `SET lock:<oturum-id> <rastgele-sahiplik-değeri> NX PX 15000`.
     Alınamazsa kısa aralıklarla (ör. 100 ms) bekle, toplam bekleme
     `refreshBudget`'ı geçmesin; sonra oturumu yeniden oku (başka replika
     yenilemiş olabilir).
  2. **Lease, işten belirgin uzun:** lease 15 sn; tek token isteği 5 sn
     (`tokenRequestTimeout`), tüm refresh + `Save` 10 sn (`refreshBudget`).
     Lease, iş bitmeden düşmemeli — düşerse ikinci replika aynı refresh
     token'ı gönderir ve reuse detection oturumu iptal eder.
  3. **Bırak:** yalnız sahibi bırakır — compare-and-delete:
     ```lua
     if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end
     ```
  4. **Lease kaybı güvenlidir — kilit doğruluk değil verim içindir:** asıl
     koruma §6.2'deki iki kuraldır. Lease düşüp ikinci bir replika kilidi
     alsa bile oturumda `RefreshPending` görür ve token'ı **göndermez**;
     birincinin sonucu ise sürüm koşuluyla yazılır (araya giren her yazma onu
     `errConflict`'e düşürür). Kilit yalnız eşzamanlı isteklerin gereksiz yere
     oturumu sonlandırmasını önler.
- Kullanıcı deposunu `users.SQLStore{DB: db}` yap ve `users.PostgresSchema`'yı
  migration olarak ekle.
- Yerel geliştirmede `http://localhost` redirect URI'si kayıtlı olmalı
  (confidential client'ta geçerlidir, §3); çerez o zaman `Secure` olmadan
  kurulur.

### 6.4 Frontend'in BFF ile konuşması

```js
// sayfa açılışında — ÖNCE HTTP durumu, sonra gövde
const r = await fetch('/auth/me')
if (r.status === 503) { /* oturum deposu geçici olarak erişilemez — login'e ATMA, tekrar dene göster */ }
else {
  const me = await r.json()                             // {authenticated, sub, name, gender}
  if (!me.authenticated) location.href = '/auth/login?returnTo=' + encodeURIComponent(location.pathname)
}

// API çağrısı — çerez kendiliğinden gider, token yok
const res = await fetch('/api/raporlar')
if (res.status === 401) location.href = '/auth/login?returnTo=' + encodeURIComponent(location.pathname)
if (res.status === 503) { /* geçici sorun — çıkışa ZORLAMA, tekrar dene göster */ }
```

```html
<form method="post" action="/auth/logout"><button>Çıkış</button></form>
```

Frontend aynı origin'den servis edilmeli (ya da aynı site altında bir reverse
proxy arkasında), yoksa `SameSite=Lax` çerez API çağrılarında gitmez.

---

## 7. Yetki modeli — `Can(rol, hedefler…)`

Access token her rol için **kendi kapsamını** taşır:

```json
"hayrat_grants": [
  { "role": "moderator", "scopes": [{ "type": "province", "id": 6 }] },
  { "role": "viewer",    "scopes": [] }
]
```

| Çağrı | Sonuç | Neden |
|---|---|---|
| `p.Can("moderator", province(6))` | `true` | Grant birebir kapsıyor |
| `p.Can("moderator", province(35))` | `false` | Moderatörlüğün kapsamı 6 |
| `p.Can("viewer")` | `true` | Boş `scopes` = proje geneli |
| `p.Can("viewer", province(35))` | `true` | Proje geneli her hedefi kapsar |
| `p.Can("moderator")` | `false` | Kapsamlı rol proje geneli **değildir** |
| `p.Can("moderator", a, b)` | a **ve** b kapsanıyorsa `true` | Çoklu hedef = AND |

- **`HasRole`/`InScope` yok ve yazılmayacak.** `hasRole("moderator") &&
  inScope(İzmir)` kimsenin vermediği bir yetkiyi (İzmir'de moderatörlük)
  verir. Projende böyle bir yardımcı **yazma**.
- `p.Grants` yalnız **listeleme** içindir (menü, `WHERE district_id IN (…)`).
  Rol listesi ve kapsam listesi diye ikiye düzleştirme.
- **Hiyerarşi:** SDK "il, ilçelerini kapsar" bilgisini bilmez; eşleşme
  `(type, id)` üzerinde birebirdir. Gerekiyorsa `Config.Resolver` ver:

  ```go
  type geo struct{ districtsByProvince map[int64][]int64 }

  func (g geo) Covers(granted, target hesabim.Scope) bool {
      if granted.Type != hesabim.ScopeTypeProvince || target.Type != hesabim.ScopeTypeDistrict {
          return false
      }
      return slices.Contains(g.districtsByProvince[granted.ID], target.ID)
  }
  ```

  `Covers` yalnız birebir eşleşme başarısız olunca çağrılır, eşzamanlı güvenli
  olmalı. Veri kendi coğrafya tablolarından gelir.
- Frontend'deki `can()` yalnız buton gizlemek içindir; **yetki kararı her
  zaman backend'de `p.Can`'dir.**

---

## 8. Token sözleşmesi ve süreler

### 8.1 Access token (JWT, ES256)

| Claim | Değer |
|---|---|
| `iss` | `https://hesabim.hayrat.com` |
| `aud` | `api:<proje-key>` — tek değer; başka projenin token'ı senin API'nde geçmez |
| `sub` | Kullanıcının kalıcı UUID'si → `Principal.Subject` |
| `client_id` | Token'ı alan client → `Principal.ClientID` |
| `sid` | Oturum id'si → `Principal.SessionID` |
| `amr` | Bugün `["otp"]` → `Principal.AMR` |
| `exp`, `iat`, `nbf`, `jti` | Standart |
| `hayrat_ver` | Sözleşme sürümü, `1`. Başka bir değer reddedilir |
| `hayrat_grants` | §7 → `Principal.Grants` |
| `hayrat_profile_ver` | Kullanıcının profil sürümü → `Principal.ProfileVersion` (yoksa 0; hiçbir zaman ret sebebi değil) |

### 8.2 ID token (`openid profile`)

`sub`, `name` (ad + soyad **tek alan**), `gender` (`male` | `female`),
`hayrat_profile_ver`, `sid`, `nonce` ve standart claim'ler. Başka profil alanı
yoktur.

**Profil tazeliği:** `name`/`gender`'ı her girişte upsert et. Ek olarak
saklanan profil sürümünü tut; gelen `ProfileVersion` saklanandan büyükse
kullanıcının profili Hesabım'da değişmiştir — bir sonraki
girişte/senkronizasyonda güncellenir.

### 8.3 Süreler

| Ne | Süre | Not |
|---|---|---|
| Authorization code | 2 dk | Tek kullanımlık |
| Başlatılmış login isteği | 10 dk | |
| **Access token** | **10 dk** | Rol değişikliği en geç bu kadar sonra yansır |
| SSO oturumu | **90 gün, kayan** | Her refresh uzatır; düzenli kullanan yeniden giriş yapmaz |
| Refresh token | Oturumun kalan ömrü | Her kullanımda döner (rotasyon) |

Grant'ler her refresh'te yeniden hesaplanır; geri alınan bir rol en geç
10 dakikada düşer.

### 8.4 Kesinlikle olmayanlar (tasarım kararı, eksik değil)

- **`/userinfo` yok.** Profil ID token'dan okunur.
- **E-posta ve telefon hiçbir token'da yok**, `email`/`phone`/`address` scope'u
  yok. Gerekiyorsa uygulama kendisi sorar.
- **Servis-servis token yok.** Bu SDK'larla entegre edilen uygulama
  client'larına `client_credentials` verilmez; bir backend kendi adına token
  alamaz. SDK böyle bir token'ı API'de kabul de etmez.
- **Introspection ve revocation uçları yok.** Doğrulama JWKS ile yereldir.
- **Back-channel logout yok.** IdP'de oturum kapanınca uygulamaya haber
  gelmez: refresh token anında ölür (`invalid_grant`), elde kalan access token
  `exp`'ine kadar (≤ 10 dk) geçerlidir.
- **Kullanıcı listeleme/arama API'si yok** — bkz. §9.

---

## 9. Kullanıcı verisi — `sub` senin anahtarındır

- `sub` kalıcıdır, yeniden kullanılmaz, kullanıcı e-posta/telefon değiştirse
  de değişmez. Kendi tablolarında kullanıcıyı **bununla** anahtarla — e-posta
  ya da telefonla değil.
- Hesabım bir kullanıcı dizini değildir; uygulama kendi projeksiyonunu tutar:

  ```sql
  CREATE TABLE users (
      sub          UUID PRIMARY KEY,
      name         TEXT        NOT NULL DEFAULT '',
      gender       TEXT        NOT NULL DEFAULT '' CHECK (gender IN ('', 'male', 'female')),
      profile_ver  BIGINT      NOT NULL DEFAULT 0,   -- hayrat_profile_ver, access token'dan
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  ```

  Satır ilk girişte açılır, her girişte güncellenir (A: `/api/me/sync`, B:
  callback). Uygulamaya özgü her şey (sınıf, okul, tercih…) bu tabloda ya da
  yanındakilerde yaşar.
- **Hiç giriş yapmamış birinin adını gösteremezsin.** Göç edilen bir
  uygulamada geçmiş verinin sahipleri gerekiyorsa bu bir kerelik veri devridir;
  Hesabım yöneticisiyle ayrıca konuşulur.
- Projede zaten kullanıcı tablosu varsa yeni tablo açma: `sub UUID UNIQUE`
  kolonu ekle, ilk girişte eşle. Eski kullanıcıları `sub`'a eşleme yöntemi
  (ör. eski sistemle ortak UUID) yöneticiyle teyit edilmeden **varsayılmaz**.

---

## 10. Kapsam sözlüğü

`scope.type` yalnızca: `region` · `province` · `district` · `school`
(`hesabim.ScopeTypeRegion`, `ScopeTypeProvince`, `ScopeTypeDistrict`,
`ScopeTypeSchool`).

- **Ülke seviyesi yok.** "Tüm ülke" = **kapsamsız rol** (proje geneli).
- Üniversite/bölüm gibi seviyeler kapsam hedefi değildir; uygulamanın kendi
  verisinde kalır.
- `scope.id`, Hesabım referans verisindeki id'dir. Uygulamanın yer kayıtlarıyla
  eşleme gerekiyorsa eşleme listesini Hesabım yöneticisinden iste.

---

## 11. Kontrol listesi

**Kayıt (yönetici):**
- [ ] Proje key'i kesin (değiştirilemez); audience `api:<key>`
- [ ] Client tipi doğru (A → `public`, B → `confidential`)
- [ ] `redirect_uris` ve `post_logout_redirect_uris` prod **ve** yerel için birebir (A: `https://localhost`, B: `http://localhost` — §3)
- [ ] Roller tanımlı, test kullanıcısına rol (+ gerekiyorsa kapsam) atanmış
- [ ] (B) Secret güvenli kanaldan alındı, secret deposuna kondu

**Kod:**
- [ ] `hesabim.New` başlangıçta bir kez; hata → süreç başlamaz
- [ ] `HESABIM_AUDIENCE` = `api:<key>` birebir
- [ ] Korunan rotalar SDK middleware'inin arkasında; header elle ayrıştırılmıyor
- [ ] Yetki kontrolleri `p.Can(rol, hedef)`; `HasRole` benzeri yardımcı yok
- [ ] Hiyerarşi gerekiyorsa `Config.Resolver`
- [ ] Kullanıcılar `sub` ile anahtarlı; ilk girişte upsert
- [ ] (A) `POST /api/me/sync` var, `sub` ve `profile_ver` token'dan geliyor
- [ ] (A) SPA başka origin'deyse CORS katmanı auth'un **önünde**, origin listesi birebir (§5.7)
- [ ] (B) PKCE + state + nonce; refresh rotasyonu saklanıyor; yenileme oturum başına kilitli
- [ ] (B) `invalid_grant` ve sonucu belirsiz refresh → oturum sonlandırılır, harcanmış token tekrar gönderilmez; istek hiç gitmediyse ya da depo erişilemezse → 503, oturum korunur
- [ ] (B) Refresh + `Save` istekten ayrılmış context'te, süre sınırlı; çok replikada dağıtık kilit §6.3'teki gibi
- [ ] (B) `/auth/login` mevcut oturumu silmiyor
- [ ] (B) `RefreshPending` token isteğinden önce kaydediliyor; `Store.Save` sürüm koşullu ve atomik (Redis'te tek Lua betiği)
- [ ] (B) Çerez `HttpOnly`, `SameSite=Lax`, prod'da `Secure`; CSRF koruması açık
- [ ] Hiçbir dosyada secret yok; hiçbir log satırında token/secret yok

---

## 12. Sık yapılan hatalar

| Belirti | Sebep |
|---|---|
| Token alınıyor ama API hep 401 | `HESABIM_AUDIENCE` yanlış — `api:` öneki dahil birebir olmalı |
| `invalid redirect_uri` | Tam string eşleşmesi: sondaki `/`, port, `http`/`https` |
| `code_challenge is required` | PKCE confidential client'ta da zorunlu |
| `hesabim.New` başlangıçta hata | Issuer'a erişilemiyor ya da yanlış issuer; `iss` discovery belgesindeki değerle bayt bayt karşılaştırılır |
| Kullanıcılar rastgele çıkış yapıyor (B) | Refresh rotasyonu saklanmıyor, eşzamanlı iki yenileme ya da sonucu belirsiz bir refresh'in tekrar denenmesi → reuse detection oturumu iptal etti |
| Ayrı origin'deki SPA'dan her API çağrısı CORS hatası / preflight 401 (A) | API'de CORS yok ya da CORS katmanı auth middleware'inin arkasında (§5.7) |
| Yerelde SPA girişi `redirect_uri is http and is not allowed` (A) | Public client'ta `http://localhost` canlı IdP'de geçmez; `https://localhost` kaydet, dev sunucusunu HTTPS ile çalıştır (§3) |
| Ağ titremesinde herkes login'e atılıyor | Geçici hata (`503`) da `401` gibi ele alınmış |
| Kapsamlı rol "proje geneli" sanılıyor | `Can("moderator")` kapsamlı grant için `false` döner — kasıtlı |
| İlçe hedefi il moderatörüne 403 | `Resolver` verilmemiş; SDK hiyerarşi bilmez |
| Token'da e-posta/telefon aranıyor | Yok ve gelmeyecek (§8.4) |
| Tarayıcıda IdP'nin `/oauth/token`'ına istek CORS hatası (A) | Origin kayıtlı `redirect_uris`'ten türer; URI kayıtlı değil, `http` (sayılmaz) ya da kayıt yeni (~1 dk) |
| 401 gövdesinde ayrıntı yok | Kasıtlı; SDK hata nedenini istemciye sızdırmaz, sunucu logunda görünür |

---

## 13. Doğrulama — bitirince çalıştır

1. `go build ./... && go vet ./... && go test ./...` yeşil.
2. Test yaz (örneklerdeki `main_test.go`'lar şablondur — sahte bir IdP ile
   gerçek imzalı token üretirler; `examples/internal/fakeidp` paketini projene
   `internal/testutil/fakeidp` olarak kopyalayabilirsin): token yok → 401,
   başka audience → 401, yetkisiz kapsam → 403, yetkili → 200;
   (B) state uyuşmazlığı → 400, `invalid_grant` → 401 + oturum silinmiş,
   5xx sonrası refresh → 401 ve token tekrar gönderilmemiş, depo hatası →
   503 + çerez korunmuş (`examples/bff/resilience_test.go` şablondur).
3. Env'ler eksikken süreç başlamamalı ve yalnız değişken adını loglamalı.
4. Gerçek değerler geldiyse uçtan uca: (A) SPA'dan giriş → `GET /api/me` 200;
   (B) `/auth/login` → giriş → `/auth/me` `authenticated: true` →
   `POST /auth/logout` Hesabım çıkış sayfasına/`post_logout_redirect_uri`'ye
   döner.
5. `git grep -nE "HESABIM_CLIENT_SECRET=.+|BEGIN .*PRIVATE KEY"` boş olmalı
   (placeholder `change-me` hariç).

## 14. Bitiş raporu (ajan)

Raporda şunlar olsun:

- Seçilen topoloji ve gerekçesi.
- Eklenen/değişen dosyalar.
- Doldurulmuş **kayıt talebi metni** (§3).
- **Yöneticiden beklenen değerler:** `client_id`, audience, (B) client secret
  — hangi env'e konacağı ile.
- Çalıştırılan doğrulamalar ve sonuçları; çalıştırılamayanlar ve nedeni.
