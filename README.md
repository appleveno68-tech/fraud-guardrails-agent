# Fraud & Guardrails Agent

واجهة محاكاة كاملة لطبقة حماية عمليات الدفع، مع Backend Python وواجهة Dashboard في ملف `app.py`.

## التشغيل

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

افتح `http://localhost:8000`.

## ربط Amazon Bedrock

انسخ `.env.example` إلى `.env` أو اضبط متغيرات البيئة في جلسة التشغيل. لا تضع المفاتيح داخل الكود أو Git. عند غياب بيانات AWS تعمل الواجهة بوضع المحاكاة المحلي، وعند توفرها تستدعي `boto3` نموذج Bedrock المحدد في `BEDROCK_MODEL_ID`.

> ملاحظة: Strands Decider 2B ممثل هنا بعقد `intervention_handler` ومحرك قرار محاكى لأغراض العرض؛ يمكن استبدال جسم القرار باستدعاء النموذج/الوكيل المعتمد في بيئة الهاكاثون.

لتفعيل تأكيد الهوية الحقيقي عبر SMS، اضبط `VERIFICATION_PHONE_NUMBER` برقم موثق في Amazon SNS، وامنح مستخدم AWS صلاحية `sns:Publish`. قد تكون حسابات SNS الجديدة في SMS Sandbox وتحتاج إضافة الرقم الموثق أولاً.

## تشغيل Strands Decider 2B الحقيقي

النظام يستخدم `STRANDS_DECIDER_URL` إذا كان مضبوطاً. شغّل خادم النموذج الرسمي على منفذ منفصل، ثم اضبط المتغير على عنوانه. عند غياب العنوان فقط يستخدم المشروع fallback محلياً لأغراض العرض. النموذج يتخذ القرار، وBedrock يكتب الرسالة؛ لا يتم استخدام Bedrock لاتخاذ قرار الاحتيال نفسه.
