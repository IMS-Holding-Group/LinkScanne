var translations = {
    ar: {
        // Page Titles
        'page.title.index': 'LinkScanne - نظام تحليل الروابط الذكي',
        'page.title.result': 'نتائج التحليل - LinkScanne',
        'page.title.about': 'عن المشروع - LinkScanne',
        'page.title.login': 'تسجيل الدخول - LinkScanne',
        'page.title.register': 'إنشاء حساب - LinkScanne',
        'page.title.payment': 'الاشتراك المميز - LinkScanne',
        
        // Navigation
        'nav.home': 'الرئيسية',
        'nav.about': 'عن المشروع',
        'nav.login': 'تسجيل الدخول',
        'nav.register': 'إنشاء حساب',
        'nav.language': 'English',
        
        // Main Page
        'main.analyze': 'تحليل الرابط',
        'main.analyze.desc': 'أدخل الرابط المراد تحليله وسيتم فحصه باستخدام تقنيات متعددة: التعلم الآلي، التحليل الديناميكي (محاكاة Sandbox)، VirusTotal، والتحليل الاستدلالي',
        'main.analyze.placeholder': 'أدخل الرابط المراد تحليله...',
        'main.analyze.button': 'تحليل',
        'main.analyze.loading': 'جاري تحليل الرابط....',
        'main.stats': 'الإحصائيات',
        'main.stats.desc': 'إحصائيات شاملة عن جميع الروابط التي تم تحليلها في النظام',
        'main.stats.total': 'إجمالي الروابط',
        'main.stats.malicious': 'روابط خبيثة',
        'main.stats.suspicious': 'روابط مشبوهة',
        'main.stats.safe': 'روابط سليمة',
        'main.stats.analyses.total': 'إجمالي التحليلات',
        'main.stats.analyses.today': 'تحليلات اليوم',
        'main.alerts': 'التنبيهات النشطة',
        'main.alerts.desc': 'تنبيهات فورية عند اكتشاف روابط مشبوهة أو خبيثة',
        'main.alerts.empty': 'لا توجد تنبيهات نشطة',
        'main.history.title': 'سجل التحليلات',
        'main.history.desc': 'عرض جميع التحليلات السابقة مع التفاصيل الكاملة والتواريخ',
        'main.history.loading': 'جاري تحميل السجلات...',
        'main.history.empty': 'لا توجد تحليلات محفوظة',
        'main.history.view': 'عرض التفاصيل',
        'main.history.read': 'قراءة التحليل',
        'main.history.date': 'التاريخ',
        'main.history.url': 'الرابط',
        'main.history.result': 'النتيجة',
        'main.history.score': 'النسبة',
        'main.history.gregorian': 'الميلادي',
        'main.history.hijri': 'الهجري',
        
        // Payment
        'payment.title': 'الاشتراك المميز',
        'payment.subtitle': 'احصل على تحليل تفصيلي كامل مع جميع الميزات المتقدمة',
        'payment.plan.free': 'الخطة المجانية',
        'payment.plan.premium': 'الخطة المميزة',
        'payment.currency': 'ريال',
        'payment.current': 'الحالية',
        'payment.subscribe': 'اشترك الآن',
        'payment.features.basic': 'تحليل أساسي للروابط',
        'payment.features.result': 'نتيجة بسيطة (سليم/مشبوه/خبيث)',
        'payment.features.detailed': 'تحليل تفصيلي كامل',
        'payment.features.history': 'سجل التحليلات',
        'payment.features.stats': 'إحصائيات متقدمة',
        'payment.features.alerts': 'تنبيهات فورية',
        'payment.features.virustotal': 'تكامل VirusTotal',
        'payment.features.support': 'دعم فني مخصص',
        'payment.methods.title': 'طرق الدفع',
        'payment.methods.card': 'بطاقة ائتمانية',
        'payment.methods.bank': 'تحويل بنكي',
        'payment.methods.manual': 'دفع يدوي',
        'payment.proceed': 'متابعة الدفع',
        
        // Results
        'results.title': 'نتائج التحليل',
        'results.final.classification': 'التصنيف النهائي',
        'results.final.score': 'النتيجة النهائية',
        'results.ml.status': 'التحليل الآلي',
        'results.dynamic.score': 'التحليل الديناميكي',
        'results.ml.title': 'تحليل التعلم الآلي',
        'results.ml.classification': 'التصنيف',
        'results.ml.confidence': 'الثقة',
        'results.ml.probabilities': 'الاحتمالات',
        'results.ml.safe': 'سليم',
        'results.ml.suspicious': 'مشبوه',
        'results.ml.malicious': 'خبيث',
        'results.dynamic.title': 'التحليل الديناميكي',
        'results.dynamic.result': 'النتيجة',
        'results.dynamic.suspicious': 'المؤشرات المشبوهة',
        'results.dynamic.total': 'إجمالي المؤشرات',
        'results.dynamic.events': 'الأحداث المكتشفة',
        'results.dynamic.downloads': 'التحميلات',
        'results.dynamic.forms': 'النماذج',
        'results.dynamic.redirects': 'إعادة التوجيه',
        'results.dynamic.js': 'JavaScript مشبوه',
        'results.dynamic.cookies': 'الكوكيز',
        'results.vt.title': 'تحليل VirusTotal',
        'results.vt.result': 'النتيجة',
        'results.vt.malicious': 'المحركات الخبيثة',
        'results.vt.status': 'الحالة',
        'results.vt.message': 'الرسالة',
        'results.vt.report': 'عرض التقرير الكامل',
        'results.heuristic.title': 'التحليل الاستدلالي',
        'results.heuristic.result': 'النتيجة',
        'results.heuristic.desc': 'يتم تحليل الرابط بناءً على الأنماط المشبوهة المعروفة',
        'results.weights.title': 'الأوزان المستخدمة',
        'results.weights.ml': 'التعلم الآلي',
        'results.weights.dynamic': 'التحليل الديناميكي',
        'results.weights.vt': 'VirusTotal',
        'results.weights.heuristic': 'الاستدلالي',
        'results.speak': 'قراءة النتائج صوتياً',
        'results.stop': 'إيقاف القراءة',
        'results.details': 'عرض التفاصيل الكاملة',
        'results.sandbox.note': 'ملاحظة: التحليل الديناميكي في هذا المشروع (مشروع التخرج) يعتمد على محاكاة Sandbox وليس تنفيذ فعلي',
        
        // Labels
        'label.safe': 'سليم',
        'label.suspicious': 'مشبوه',
        'label.malicious': 'خبيث',
        'label.error': 'خطأ',
        
        // Status
        'status.clean': 'سليم',
        'status.malicious': 'خبيث',
        'status.suspicious': 'مشبوه',
        'status.unknown': 'غير معروف',
        'status.safe': 'الرابط سليم',
        
        // About Page
        'about.title': 'LinkScanne',
        'about.subtitle': 'نظام تحليل الروابط الذكي والحماية من التهديدات السيبرانية',
        'about.overview': 'نظرة عامة على المشروع',
        'about.overview.text': 'LinkScanne هو نظام ويب متطور ومتكامل مصمم لتحليل الروابط واكتشاف التهديدات السيبرانية باستخدام أحدث تقنيات الذكاء الاصطناعي والتعلم الآلي. يهدف المشروع إلى توفير حماية شاملة للمستخدمين من الروابط الخبيثة والمواقع المشبوهة.',
        'about.important': 'معلومات مهمة',
        'about.important.accuracy': 'دقة التحليل',
        'about.important.accuracy.text': 'النظام يحقق دقة عالية تصل إلى 95% في تصنيف الروابط',
        'about.important.speed': 'سرعة التحليل',
        'about.important.speed.text': 'يستغرق التحليل عادة من 5 إلى 15 ثانية حسب تعقيد الرابط',
        'about.important.privacy': 'الخصوصية',
        'about.important.privacy.text': 'جميع البيانات محفوظة محلياً ولا يتم إرسالها لخوادم خارجية',
        'about.important.accessibility': 'إمكانية الوصول',
        'about.important.accessibility.text': 'يدعم النظام القراءة الصوتية للكفيفين وضعاف البصر',
        'about.features': 'الميزات',
        'about.features.ai': 'الذكاء الاصطناعي',
        'about.features.ai.text': 'استخدام نماذج التعلم الآلي المتقدمة لتصنيف الروابط بناءً على الميزات اللغوية والإحصائية',
        'about.features.dynamic': 'التحليل الديناميكي',
        'about.features.dynamic.text': 'فحص سلوك الروابط في بيئة Sandbox آمنة لمراقبة الأنشطة المشبوهة',
        'about.features.dynamic.note': 'ملاحظة: بيئة Sandbox في هذا المشروع (مشروع التخرج) هي محاكاة فقط ولا تقوم بتنفيذ فعلي للكود',
        'about.features.vt': 'VirusTotal Integration',
        'about.features.vt.text': 'التكامل مع قاعدة البيانات العالمية للروابط الخبيثة للحصول على أحدث المعلومات',
        'about.features.alerts': 'نظام التنبيهات',
        'about.features.alerts.text': 'مراقبة فورية وإشعارات تلقائية عند اكتشاف أنماط خطيرة أو مشبوهة',
        'about.tech': 'التقنيات المستخدمة',
        'about.workflow': 'كيفية عمل النظام',
        'about.workflow.step1': 'إدخال الرابط',
        'about.workflow.step1.text': 'يقوم المستخدم بإدخال الرابط المراد تحليله في واجهة النظام',
        'about.workflow.step2': 'التحليل متعدد المستويات',
        'about.workflow.step2.text': 'يتم تحليل الرابط باستخدام أربع طرق مختلفة: التعلم الآلي، التحليل الديناميكي (محاكاة Sandbox)، VirusTotal، والتحليل الاستدلالي',
        'about.workflow.step2.note': 'ملاحظة: التحليل الديناميكي في هذا المشروع (مشروع التخرج) يعتمد على محاكاة وليس تنفيذ فعلي',
        'about.workflow.step3': 'دمج النتائج',
        'about.workflow.step3.text': 'يتم دمج جميع النتائج باستخدام أوزان محددة لحساب النتيجة النهائية',
        'about.workflow.step4': 'التصنيف النهائي',
        'about.workflow.step4.text': 'يتم تصنيف الرابط كـ سليم، مشبوه، أو خبيث بناءً على النتيجة المحسوبة',
        'about.workflow.step5': 'عرض النتائج',
        'about.workflow.step5.text': 'يتم عرض النتائج التفصيلية للمستخدم مع إمكانية حفظها (للمستخدمين المسجلين)',
        'about.security': 'ميزات الأمان',
        'about.security.isolated': 'البيئة المعزولة',
        'about.security.isolated.text': 'جميع عمليات التحليل تتم في بيئة Sandbox آمنة ومعزولة',
        'about.security.isolated.note': 'ملاحظة: في هذا المشروع (مشروع التخرج)، بيئة Sandbox هي محاكاة فقط',
        'about.security.local': 'البيانات المحلية',
        'about.security.local.text': 'جميع البيانات والنتائج محفوظة محلياً ولا يتم إرسالها لخوادم خارجية',
        'about.security.privacy': 'الخصوصية',
        'about.security.privacy.text': 'لا يتم تتبع أو حفظ معلومات المستخدمين الشخصية',
        'about.security.monitoring': 'المراقبة المستمرة',
        'about.security.monitoring.text': 'نظام تنبيهات ذكي لمراقبة الأنماط المشبوهة والتهديدات الجديدة',
        'about.goals': 'الأهداف والرؤية',
        'about.goals.protection': 'الحماية الشاملة',
        'about.goals.protection.text': 'توفير حماية شاملة ومتكاملة من جميع أنواع التهديدات السيبرانية',
        'about.goals.usability': 'سهولة الاستخدام',
        'about.goals.usability.text': 'واجهة مستخدم بسيطة وسهلة الاستخدام لجميع المستخدمين',
        'about.goals.performance': 'الأداء العالي',
        'about.goals.performance.text': 'تحليل سريع ودقيق للروابط مع استهلاك موارد محدود',
        'about.goals.development': 'التطوير المستمر',
        'about.goals.development.text': 'تحديث وتحسين النظام باستمرار لمواجهة التهديدات الجديدة',
        'about.accessibility': 'إمكانية الوصول وقراءة النتائج صوتياً',
        'about.accessibility.vision': 'دعم الكفيفين وضعاف البصر',
        'about.accessibility.vision.text': 'يقدم LinkScanne ميزة متقدمة لقراءة نتائج التحليل صوتياً باستخدام Web Speech API، مما يتيح للمستخدمين الكفيفين وضعاف البصر الاستماع إلى النتائج التفصيلية بدلاً من قراءتها.',
        'about.accessibility.detailed': 'القراءة التفصيلية',
        'about.accessibility.detailed.text': 'تتضمن القراءة الصوتية جميع تفاصيل التحليل: التصنيف النهائي، نتائج التعلم الآلي مع الاحتمالات، نتائج التحليل الديناميكي مع الأحداث المكتشفة، نتائج VirusTotal، والتحليل الاستدلالي.',
        'about.accessibility.easy': 'سهولة الاستخدام',
        'about.accessibility.easy.text': 'يمكن تفعيل أو إيقاف القراءة الصوتية بسهولة من خلال الأزرار المخصصة في صفحة النتائج. يتم حفظ تفضيلات المستخدم محلياً.',
        'about.accessibility.arabic': 'دعم اللغة العربية',
        'about.accessibility.arabic.text': 'القراءة الصوتية تدعم اللغة العربية بالكامل مع نطق صحيح للمصطلحات التقنية والنتائج.',
        'about.faq': 'الأسئلة الشائعة',
        'about.faq.safe': 'هل النظام آمن للاستخدام؟',
        'about.faq.safe.text': 'نعم، النظام آمن تماماً. جميع العمليات تتم محلياً ولا يتم إرسال أي بيانات شخصية لخوادم خارجية.',
        'about.faq.accuracy': 'ما هي دقة التحليل؟',
        'about.faq.accuracy.text': 'النظام يحقق دقة عالية تصل إلى 95% في تصنيف الروابط باستخدام تقنيات متعددة ومتقدمة.',
        'about.faq.save': 'هل يمكن حفظ النتائج؟',
        'about.faq.save.text': 'نعم، يمكن للمستخدمين المسجلين حفظ نتائج التحليل والرجوع إليها لاحقاً.',
        'about.faq.speed': 'ما هي سرعة التحليل؟',
        'about.faq.speed.text': 'يستغرق التحليل عادة من 5 إلى 15 ثانية حسب تعقيد الرابط وطبيعة التحليل المطلوب.',
        
        // Footer
        'footer.text': '© 2025 LinkScanne - نظام تحليل الروابط الذكي',
        
        // Errors
        'error.loading': 'فشل في تحميل النتائج',
        'error.noId': 'معرف التحليل غير موجود',
        'error.server': 'خطأ في الاتصال بالخادم',
        'error.analysis': 'خطأ في تحليل الرابط',
        
        // Voice
        'voice.result': 'النتيجة: الرابط',
        'voice.percentage': 'بالمئة',
        'voice.analyzed': 'الرابط المُحلّل',
        'voice.detailed': 'نتائج التحليل التفصيلية',
        'voice.final.classification': 'التصنيف النهائي',
        'voice.final.result': 'النتيجة النهائية',
        'voice.ml': 'تحليل التعلم الآلي',
        'voice.ml.classification': 'التصنيف',
        'voice.ml.confidence': 'الثقة',
        'voice.ml.probability': 'احتمالية',
        'voice.dynamic': 'التحليل الديناميكي',
        'voice.dynamic.result': 'النتيجة',
        'voice.dynamic.suspicious': 'المؤشرات المشبوهة',
        'voice.dynamic.total': 'من إجمالي',
        'voice.dynamic.events': 'الأحداث المكتشفة',
        'voice.dynamic.downloads': 'التحميلات',
        'voice.dynamic.forms': 'النماذج',
        'voice.dynamic.redirects': 'إعادة التوجيه',
        'voice.dynamic.js': 'JavaScript مشبوه',
        'voice.dynamic.cookies': 'الكوكيز',
        'voice.vt': 'تحليل VirusTotal',
        'voice.vt.result': 'النتيجة',
        'voice.vt.malicious': 'المحركات الخبيثة',
        'voice.vt.status': 'الحالة',
        'voice.heuristic': 'التحليل الاستدلالي',
        'voice.heuristic.result': 'النتيجة'
    },
    en: {
        // Page Titles
        'page.title.index': 'LinkScanne - Smart Link Analysis System',
        'page.title.result': 'Analysis Results - LinkScanne',
        'page.title.about': 'About Project - LinkScanne',
        'page.title.login': 'Login - LinkScanne',
        'page.title.register': 'Sign Up - LinkScanne',
        'page.title.payment': 'Premium Subscription - LinkScanne',
        
        // Navigation
        'nav.home': 'Home',
        'nav.about': 'About',
        'nav.login': 'Login',
        'nav.register': 'Sign Up',
        'nav.language': 'العربية',
        
        // Main Page
        'main.analyze': 'Analyze Link',
        'main.analyze.desc': 'Enter the link to be analyzed and it will be scanned using multiple techniques: Machine Learning, Dynamic Analysis (Sandbox simulation), VirusTotal, and Heuristic Analysis',
        'main.analyze.placeholder': 'Enter the link to analyze...',
        'main.analyze.button': 'Analyze',
        'main.analyze.loading': 'Analyzing link....',
        'main.stats': 'Statistics',
        'main.stats.desc': 'Comprehensive statistics about all links analyzed in the system',
        'main.stats.total': 'Total Links',
        'main.stats.malicious': 'Malicious Links',
        'main.stats.suspicious': 'Suspicious Links',
        'main.stats.safe': 'Safe Links',
        'main.stats.analyses.total': 'Total Analyses',
        'main.stats.analyses.today': 'Today\'s Analyses',
        'main.alerts': 'Active Alerts',
        'main.alerts.desc': 'Instant alerts when suspicious or malicious links are detected',
        'main.alerts.empty': 'No active alerts',
        'main.history.title': 'Analysis History',
        'main.history.desc': 'View all previous analyses with full details and dates',
        'main.history.loading': 'Loading records...',
        'main.history.empty': 'No saved analyses',
        'main.history.view': 'View Details',
        'main.history.read': 'Read Analysis',
        'main.history.delete': 'Delete',
        'main.history.date': 'Date',
        'main.history.url': 'URL',
        'main.history.result': 'Result',
        'main.history.score': 'Score',
        'main.history.gregorian': 'Gregorian',
        'main.history.hijri': 'Hijri',
        
        // Payment
        'payment.title': 'Premium Subscription',
        'payment.subtitle': 'Get full detailed analysis with all advanced features',
        'payment.plan.free': 'Free Plan',
        'payment.plan.premium': 'Premium Plan',
        'payment.currency': 'SAR',
        'payment.current': 'Current',
        'payment.subscribe': 'Subscribe Now',
        'payment.features.basic': 'Basic link analysis',
        'payment.features.result': 'Simple result (safe/malicious)',
        'payment.features.detailed': 'Full detailed analysis',
        'payment.features.history': 'Analysis history',
        'payment.features.stats': 'Advanced statistics',
        'payment.features.alerts': 'Instant alerts',
        'payment.features.virustotal': 'VirusTotal integration',
        'payment.features.support': 'Dedicated support',
        'payment.methods.title': 'Payment Methods',
        'payment.methods.card': 'Credit Card',
        'payment.methods.bank': 'Bank Transfer',
        'payment.methods.manual': 'Manual Payment',
        'payment.proceed': 'Proceed to Payment',
        
        // Results
        'results.title': 'Analysis Results',
        'results.final.classification': 'Final Classification',
        'results.final.score': 'Final Result',
        'results.ml.status': 'ML Analysis',
        'results.dynamic.score': 'Dynamic Analysis',
        'results.ml.title': 'Machine Learning Analysis',
        'results.ml.classification': 'Classification',
        'results.ml.confidence': 'Confidence',
        'results.ml.probabilities': 'Probabilities',
        'results.ml.safe': 'Safe',
        'results.ml.suspicious': 'Suspicious',
        'results.ml.malicious': 'Malicious',
        'results.dynamic.title': 'Dynamic Analysis',
        'results.dynamic.result': 'Result',
        'results.dynamic.suspicious': 'Suspicious Indicators',
        'results.dynamic.total': 'Total Indicators',
        'results.dynamic.events': 'Detected Events',
        'results.dynamic.downloads': 'Downloads',
        'results.dynamic.forms': 'Forms',
        'results.dynamic.redirects': 'Redirects',
        'results.dynamic.js': 'Suspicious JavaScript',
        'results.dynamic.cookies': 'Cookies',
        'results.vt.title': 'VirusTotal Analysis',
        'results.vt.result': 'Result',
        'results.vt.malicious': 'Malicious Engines',
        'results.vt.status': 'Status',
        'results.vt.message': 'Message',
        'results.vt.report': 'View Full Report',
        'results.heuristic.title': 'Heuristic Analysis',
        'results.heuristic.result': 'Result',
        'results.heuristic.desc': 'The link is analyzed based on known suspicious patterns',
        'results.weights.title': 'Used Weights',
        'results.weights.ml': 'Machine Learning',
        'results.weights.dynamic': 'Dynamic Analysis',
        'results.weights.vt': 'VirusTotal',
        'results.weights.heuristic': 'Heuristic',
        'results.speak': 'Read Results Aloud',
        'results.stop': 'Stop Reading',
        'results.details': 'View Full Details',
        'results.sandbox.note': 'Note: Dynamic analysis in this project (graduation project) relies on Sandbox simulation and not actual execution',
        
        // Labels
        'label.safe': 'Safe',
        'label.suspicious': 'Suspicious',
        'label.malicious': 'Malicious',
        'label.error': 'Error',
        
        // Status
        'status.clean': 'clean',
        'status.malicious': 'malicious',
        'status.suspicious': 'suspicious',
        'status.unknown': 'unknown',
        'status.safe': 'Link is safe',
        
        // About Page
        'about.title': 'LinkScanne',
        'about.subtitle': 'Smart Link Analysis System and Cybersecurity Protection',
        'about.overview': 'Project Overview',
        'about.overview.text': 'LinkScanne is an advanced and integrated web system designed to analyze links and detect cyber threats using the latest artificial intelligence and machine learning technologies. The project aims to provide comprehensive protection for users from malicious links and suspicious websites.',
        'about.important': 'Important Information',
        'about.important.accuracy': 'Analysis Accuracy',
        'about.important.accuracy.text': 'The system achieves high accuracy up to 95% in link classification',
        'about.important.speed': 'Analysis Speed',
        'about.important.speed.text': 'Analysis usually takes 5 to 15 seconds depending on link complexity',
        'about.important.privacy': 'Privacy',
        'about.important.privacy.text': 'All data is stored locally and not sent to external servers',
        'about.important.accessibility': 'Accessibility',
        'about.important.accessibility.text': 'The system supports audio reading for the blind and visually impaired',
        'about.features': 'Features',
        'about.features.ai': 'Artificial Intelligence',
        'about.features.ai.text': 'Using advanced machine learning models to classify links based on linguistic and statistical features',
        'about.features.dynamic': 'Dynamic Analysis',
        'about.features.dynamic.text': 'Examining link behavior in a secure Sandbox environment to monitor suspicious activities',
        'about.features.dynamic.note': 'Note: Sandbox environment in this project (graduation project) is simulation only and does not perform actual code execution',
        'about.features.vt': 'VirusTotal Integration',
        'about.features.vt.text': 'Integration with the global database of malicious links to get the latest information',
        'about.features.alerts': 'Alert System',
        'about.features.alerts.text': 'Real-time monitoring and automatic notifications when dangerous or suspicious patterns are detected',
        'about.tech': 'Technologies Used',
        'about.workflow': 'How the System Works',
        'about.workflow.step1': 'Enter Link',
        'about.workflow.step1.text': 'User enters the link to be analyzed in the system interface',
        'about.workflow.step2': 'Multi-Level Analysis',
        'about.workflow.step2.text': 'The link is analyzed using four different methods: Machine Learning, Dynamic Analysis (Sandbox simulation), VirusTotal, and Heuristic Analysis',
        'about.workflow.step2.note': 'Note: Dynamic analysis in this project (graduation project) relies on simulation and not actual execution',
        'about.workflow.step3': 'Merge Results',
        'about.workflow.step3.text': 'All results are merged using specific weights to calculate the final result',
        'about.workflow.step4': 'Final Classification',
        'about.workflow.step4.text': 'The link is classified as safe, suspicious, or malicious based on the calculated result',
        'about.workflow.step5': 'Display Results',
        'about.workflow.step5.text': 'Detailed results are displayed to the user with the ability to save them (for registered users)',
        'about.security': 'Security Features',
        'about.security.isolated': 'Isolated Environment',
        'about.security.isolated.text': 'All analysis operations are performed in a secure and isolated Sandbox environment',
        'about.security.isolated.note': 'Note: In this project (graduation project), Sandbox environment is simulation only',
        'about.security.local': 'Local Data',
        'about.security.local.text': 'All data and results are stored locally and not sent to external servers',
        'about.security.privacy': 'Privacy',
        'about.security.privacy.text': 'User personal information is not tracked or stored',
        'about.security.monitoring': 'Continuous Monitoring',
        'about.security.monitoring.text': 'Smart alert system to monitor suspicious patterns and new threats',
        'about.goals': 'Goals and Vision',
        'about.goals.protection': 'Comprehensive Protection',
        'about.goals.protection.text': 'Providing comprehensive and integrated protection from all types of cyber threats',
        'about.goals.usability': 'Ease of Use',
        'about.goals.usability.text': 'Simple and easy-to-use interface for all users',
        'about.goals.performance': 'High Performance',
        'about.goals.performance.text': 'Fast and accurate link analysis with limited resource consumption',
        'about.goals.development': 'Continuous Development',
        'about.goals.development.text': 'Continuously updating and improving the system to face new threats',
        'about.accessibility': 'Accessibility and Audio Reading of Results',
        'about.accessibility.vision': 'Support for the Blind and Visually Impaired',
        'about.accessibility.vision.text': 'LinkScanne offers an advanced feature to read analysis results aloud using Web Speech API, allowing blind and visually impaired users to listen to detailed results instead of reading them.',
        'about.accessibility.detailed': 'Detailed Reading',
        'about.accessibility.detailed.text': 'Audio reading includes all analysis details: final classification, machine learning results with probabilities, dynamic analysis results with detected events, VirusTotal results, and heuristic analysis.',
        'about.accessibility.easy': 'Ease of Use',
        'about.accessibility.easy.text': 'Audio reading can be easily enabled or disabled through dedicated buttons on the results page. User preferences are stored locally.',
        'about.accessibility.arabic': 'Arabic Language Support',
        'about.accessibility.arabic.text': 'Audio reading fully supports Arabic with correct pronunciation of technical terms and results.',
        'about.faq': 'Frequently Asked Questions',
        'about.faq.safe': 'Is the system safe to use?',
        'about.faq.safe.text': 'Yes, the system is completely safe. All operations are performed locally and no personal data is sent to external servers.',
        'about.faq.accuracy': 'What is the analysis accuracy?',
        'about.faq.accuracy.text': 'The system achieves high accuracy up to 95% in link classification using multiple advanced techniques.',
        'about.faq.save': 'Can results be saved?',
        'about.faq.save.text': 'Yes, registered users can save analysis results and refer to them later.',
        'about.faq.speed': 'What is the analysis speed?',
        'about.faq.speed.text': 'Analysis usually takes 5 to 15 seconds depending on link complexity and required analysis type.',
        
        // Footer
        'footer.text': '© 2025 LinkScanne - Smart Link Analysis System',
        
        // Errors
        'error.loading': 'Failed to load results',
        'error.noId': 'Analysis ID not found',
        'error.server': 'Server connection error',
        'error.analysis': 'Link analysis error',
        
        // Voice
        'voice.result': 'Result: Link is',
        'voice.percentage': 'percent',
        'voice.analyzed': 'Analyzed link',
        'voice.detailed': 'Detailed analysis results',
        'voice.final.classification': 'Final classification',
        'voice.final.result': 'Final result',
        'voice.ml': 'Machine Learning analysis',
        'voice.ml.classification': 'Classification',
        'voice.ml.confidence': 'Confidence',
        'voice.ml.probability': 'Probability',
        'voice.dynamic': 'Dynamic analysis',
        'voice.dynamic.result': 'Result',
        'voice.dynamic.suspicious': 'Suspicious indicators',
        'voice.dynamic.total': 'out of total',
        'voice.dynamic.events': 'Detected events',
        'voice.dynamic.downloads': 'Downloads',
        'voice.dynamic.forms': 'Forms',
        'voice.dynamic.redirects': 'Redirects',
        'voice.dynamic.js': 'Suspicious JavaScript',
        'voice.dynamic.cookies': 'Cookies',
        'voice.vt': 'VirusTotal analysis',
        'voice.vt.result': 'Result',
        'voice.vt.malicious': 'Malicious engines',
        'voice.vt.status': 'Status',
        'voice.heuristic': 'Heuristic analysis',
        'voice.heuristic.result': 'Result'
    }
};

// اللغة الافتراضية عربية عند التحميل الأول فقط
var savedLang = localStorage.getItem('linkScanne_language');
// إذا لم تكن هناك لغة محفوظة، استخدم العربية كافتراضية
if (!savedLang || (savedLang !== 'ar' && savedLang !== 'en')) {
    localStorage.setItem('linkScanne_language', 'ar');
    savedLang = 'ar';
}
var currentLang = savedLang;

function translate(key) {
    if (!key) return key;
    // التحقق من وجود translations و currentLang
    if (!translations || !currentLang) return key;
    // محاولة الحصول على الترجمة من اللغة الحالية
    if (translations[currentLang] && translations[currentLang][key]) {
        return translations[currentLang][key];
    }
    // Fallback إلى العربية
    if (translations.ar && translations.ar[key]) {
        return translations.ar[key];
    }
    // Fallback إلى الإنجليزية إذا كانت اللغة الحالية عربية
    if (currentLang === 'ar' && translations.en && translations.en[key]) {
        return translations.en[key];
    }
    return key;
}

function setLanguage(lang) {
    // السماح فقط بالعربية أو الإنجليزية
    if (lang !== 'ar' && lang !== 'en') {
        lang = 'ar'; // الافتراضي عربي فقط إذا كانت القيمة غير صحيحة
    }
    // حفظ اللغة المختارة وتطبيقها
    currentLang = lang;
    localStorage.setItem('linkScanne_language', lang);
    applyLanguage();
}

function applyLanguage() {
    // التأكد من أن currentLang موجود
    if (!currentLang) {
        var saved = localStorage.getItem('linkScanne_language');
        if (!saved || (saved !== 'ar' && saved !== 'en')) {
            localStorage.setItem('linkScanne_language', 'ar');
            currentLang = 'ar';
        } else {
            currentLang = saved;
        }
    }
    // تحديد الاتجاه حسب اللغة المختارة
    var dir = currentLang === 'ar' ? 'rtl' : 'ltr';
    var langAttr = currentLang || 'ar';
    document.documentElement.setAttribute('dir', dir);
    document.documentElement.setAttribute('lang', langAttr);
    document.documentElement.style.direction = dir;
    
    // إضافة class للـ body أيضاً
    if (document.body) {
        document.body.setAttribute('dir', dir);
        document.body.setAttribute('lang', langAttr);
        document.body.style.direction = dir;
    }
    
    // ترجمة جميع العناصر مع data-translate
    var elements = document.querySelectorAll('[data-translate]');
    elements.forEach(function(el) {
        var key = el.getAttribute('data-translate');
        if (!key) return;
        
        var text = translate(key);
        if (!text) return;
        
        if (el.tagName === 'INPUT' && el.type !== 'submit' && el.type !== 'button') {
            el.placeholder = text;
        } else if (el.tagName === 'TITLE') {
            el.textContent = text;
        } else if (el.tagName === 'SPAN') {
            el.textContent = text;
        } else if (el.tagName === 'BUTTON') {
            // معالجة الأزرار بشكل خاص
            var html = el.innerHTML || '';
            var iconMatch = html.match(/<i[^>]*class="[^"]*"[^>]*><\/i>/);
            if (iconMatch) {
                el.innerHTML = iconMatch[0] + ' <span data-translate="' + key + '">' + text + '</span>';
            } else {
                el.innerHTML = '<span data-translate="' + key + '">' + text + '</span>';
            }
        } else {
            // معالجة العناصر الأخرى
            var html = el.innerHTML || '';
            var spanMatch = html.match(/<span[^>]*data-translate[^>]*>.*?<\/span>/);
            if (spanMatch) {
                el.innerHTML = html.replace(spanMatch[0], '<span data-translate="' + key + '">' + text + '</span>');
            } else {
                var iconMatch = html.match(/<i[^>]*class="[^"]*"[^>]*><\/i>/);
                if (iconMatch) {
                    var iconHtml = iconMatch[0];
                    el.innerHTML = iconHtml + ' <span data-translate="' + key + '">' + text + '</span>';
                } else {
                    // إذا كان العنصر يحتوي على نص فقط
                    var textNodes = Array.from(el.childNodes).filter(function(node) {
                        return node.nodeType === 3 && node.textContent.trim();
                    });
                    if (textNodes.length > 0) {
                        el.innerHTML = '<span data-translate="' + key + '">' + text + '</span>';
                    } else {
                        el.innerHTML = '<span data-translate="' + key + '">' + text + '</span>';
                    }
                }
            }
        }
    });
    
    // ترجمة title attributes
    var titleElements = document.querySelectorAll('[data-translate-title]');
    titleElements.forEach(function(el) {
        var key = el.getAttribute('data-translate-title');
        if (key) {
            var text = translate(key);
            if (text) {
                el.setAttribute('title', text);
            }
        }
    });
    
    // ترجمة title tag
    var titleTag = document.querySelector('title');
    if (titleTag && titleTag.getAttribute('data-translate')) {
        var titleKey = titleTag.getAttribute('data-translate');
        var titleText = translate(titleKey);
        if (titleText) {
            titleTag.textContent = titleText;
        }
    }
    
    // تحديث اتجاه النصوص والأزرار بناءً على اللغة
    var allButtons = document.querySelectorAll('button, a.btn, input[type="submit"], input[type="button"]');
    allButtons.forEach(function(btn) {
        // تحديث اتجاه الزر
        if (currentLang === 'ar') {
            btn.style.direction = 'rtl';
            btn.style.textAlign = 'right';
        } else {
            btn.style.direction = 'ltr';
            btn.style.textAlign = 'left';
        }
    });
    
    // تحديث اتجاه جميع العناصر
    var allElements = document.querySelectorAll('body, main, section, div, p, h1, h2, h3, h4, h5, h6');
    allElements.forEach(function(el) {
        if (el.hasAttribute('data-translate')) return;
        if (currentLang === 'ar') {
            if (!el.style.direction) {
                el.style.direction = 'rtl';
            }
        } else {
            if (!el.style.direction) {
                el.style.direction = 'ltr';
            }
        }
    });
}

if (typeof window !== 'undefined') {
    window.translate = translate;
    window.setLanguage = setLanguage;
    window.applyLanguage = applyLanguage;
    
    // دالة للحصول على اللغة الحالية بشكل آمن
    window.currentLang = function() { 
        // الحصول على اللغة الحالية من المتغير أو localStorage
        // استخدام var للوصول إلى المتغير الخارجي
        var lang = currentLang;
        if (!lang || lang === 'undefined') {
            var saved = localStorage.getItem('linkScanne_language');
            if (saved && (saved === 'ar' || saved === 'en')) {
                currentLang = saved;
                lang = saved;
            } else {
                currentLang = 'ar';
                lang = 'ar';
            }
        }
        return lang || 'ar'; 
    };
    
    // تطبيق اللغة فوراً عند تحميل الملف
    (function() {
        // التأكد من أن currentLang موجود
        var saved = localStorage.getItem('linkScanne_language');
        // إذا لم تكن هناك لغة محفوظة، استخدم العربية كافتراضية
        if (!saved || (saved !== 'ar' && saved !== 'en')) {
            localStorage.setItem('linkScanne_language', 'ar');
            currentLang = 'ar';
        } else {
            currentLang = saved;
        }
        
        // تطبيق الاتجاه حسب اللغة المختارة
        var dir = currentLang === 'ar' ? 'rtl' : 'ltr';
        var langAttr = currentLang || 'ar';
        if (document.documentElement) {
            document.documentElement.setAttribute('dir', dir);
            document.documentElement.setAttribute('lang', langAttr);
            document.documentElement.style.direction = dir;
        }
        if (document.body) {
            document.body.setAttribute('dir', dir);
            document.body.setAttribute('lang', langAttr);
            document.body.style.direction = dir;
        }
        
        // استخدام flag عالمي لمنع التطبيق المتكرر
        if (!window.languageInitialized) {
            window.languageInitialized = true;
            
            function initLanguage() {
                // التأكد من عدم التطبيق المتكرر
                if (window.languageApplied) return;
                window.languageApplied = true;
                
                function doApply() {
                    // تطبيق فوراً بدون تأخير
                    if (typeof applyLanguage === 'function') {
                        applyLanguage();
                    }
                    // تحديث زر اللغة
                    var btn = document.getElementById('language-text');
                    if (btn && typeof translate === 'function') {
                        btn.textContent = translate('nav.language');
                    }
                }
                
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', doApply);
                } else {
                    doApply();
                }
            }
            
            initLanguage();
        }
    })();
}
