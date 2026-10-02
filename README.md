# TeroDev Stalker Proxy — جاهز للنشر على Railway

هذا المستودع يحتوي خدمة الـ API فقط. ارفع محتويات هذا المجلد إلى مستودع GitHub جديد، ثم اربط المستودع بخدمة Railway.

> **تنبيه أمان:** قاعدة البيانات الأصلية `database.sqlite` لم تُضمّن في هذه الحزمة لأنها قد تحتوي رموز دخول وروابط بوابات وعناوين MAC. لا ترفع قاعدة البيانات أو ملف `.env` إلى GitHub. القاعدة الجديدة تُنشأ تلقائياً داخل الـ Volume في Railway.

## 1) ارفع الملفات إلى GitHub

1. نزّل وفك ضغط ملف ZIP.
2. أنشئ مستودعاً جديداً على GitHub. إذا ما تريد أن يكون الكود عاماً، اختَر **Private**.
3. ارفع **محتويات المجلد بعد فك الضغط** إلى جذر المستودع؛ لا ترفع ملف ZIP نفسه. لازم يكون `package.json` و`railway.json` ظاهرين مباشرة في الصفحة الرئيسية للمستودع، ويكون مجلد `src` بجانبهم.
4. تأكد أن `database.sqlite` و`.env` غير موجودين بالمستودع.

## 2) أنشئ خدمة Railway

1. في Railway اختر **New Project → Deploy from GitHub Repo**، واربط حساب GitHub إذا طلب منك، ثم اختَر المستودع.
2. افتح الخدمة ثم **Settings → Build**. خَلِّ **Root Directory** على `/` (الافتراضي)، لأن ملفات التطبيق موجودة بجذر المستودع.
3. إعدادات البناء والتشغيل:
   - Builder: **Nixpacks** (أو الإعداد الافتراضي)
   - Install/Build Command: اتركه تلقائياً؛ سيستخدم `npm ci` من `package-lock.json`.
   - Start Command: `npm start`
4. احفظ التغييرات ثم انشر الخدمة.

هذه النسخة لا تحتوي `pnpm-lock.yaml` أو `pnpm-workspace.yaml`؛ لذلك لن يحاول Railway تثبيت الحزم بواسطة pnpm.

## 3) أضف تخزيناً دائماً لقاعدة البيانات

1. من لوحة مشروع Railway أضف **Volume** واربطه بخدمة الـ proxy.
2. عيّن **Mount Path** إلى:
   ```text
   /data
   ```
3. من الخدمة افتح **Variables** وأضف:
   ```text
   DB_PATH=/data/database.sqlite
   ALLOWED_ORIGIN=https://رابط-موقعك.vercel.app
   INITIAL_ADMIN_CODE=ضع-هنا-رمزاً-سرياً-طويلاً-وعشوائياً
   ```
   استبدل قيمة `ALLOWED_ORIGIN` بعنوان موقعك الحقيقي على Vercel. إذا تريد تشغيل الـ proxy وحده بالبداية، تقدر مؤقتاً تترك `ALLOWED_ORIGIN` بقيمة `*`، وبعدها قيّدها إلى عنوان الواجهة.

`INITIAL_ADMIN_CODE` مطلوب فقط عند إنشاء قاعدة جديدة وفارغة. اختر قيمة طويلة لا تستخدمها في مكان آخر، خزّنها عندك بأمان، وانتظر في **Deployment Logs** رسالة `Initial admin access code created`. بعدها احذف المتغير `INITIAL_ADMIN_CODE` من Railway؛ يبقى حساب المدير محفوظاً في قاعدة البيانات.

## 4) أنشئ الرابط العام وافحص الخدمة

1. من **Settings → Networking** أنشئ **Generate Domain** (أو الخيار المكافئ لإنشاء نطاق عام).
2. افتح الرابط مع `/health`، مثلاً:
   ```text
   https://اسم-الخدمة.up.railway.app/health
   ```
3. المفروض يرجع ردّاً مثل:
   ```json
   {"status":"ok","uptime":12.34}
   ```

## 5) اربط الواجهة الموجودة على Vercel

في مشروع الواجهة على Vercel أضف Environment Variable:

```text
VITE_PROXY_URL=https://اسم-الخدمة.up.railway.app
```

استخدم رابط Railway من دون `/health` ومن دون `/` في نهايته، ثم نفّذ **Redeploy** للواجهة. تأكد أيضاً أن `ALLOWED_ORIGIN` في Railway يطابق رابط Vercel تماماً، ثم أعد نشر خدمة Railway إذا غيّرت المتغير.

## تذكير أمان

- لا تشارك `INITIAL_ADMIN_CODE` أو أي رموز دخول في GitHub أو المحادثات.
- رموز الدخول في مخطط SQLite الحالي محفوظة كنص عادي؛ احمِ الـ Volume والنسخ الاحتياطية.
- لا تحذف الـ Volume؛ حذف الخدمة/الـ Volume قد يؤدي إلى فقدان قاعدة البيانات.
- قاعدة البيانات القديمة غير موجودة بهذه الحزمة. إذا كنت تحتاج المستخدمين أو البوابات المحفوظة فيها، انقلها بشكل خاص إلى `/data/database.sqlite` بعد إنشاء الـ Volume؛ لا ترفعها إلى مستودع GitHub.

## تشغيل محلي للاختبار

```bash
npm ci
cp .env.example .env
npm start
```

ثم افتح `http://localhost:3001/health`. ملف `.env` مستثنى من Git تلقائياً.
