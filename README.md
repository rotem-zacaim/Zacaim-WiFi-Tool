⚡ ZACAIM V2 - Advanced WiFi Auditing Framework

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red.svg)
![License](https://img.shields.io/badge/License-Educational%20Only-yellow.svg)

**ZACAIM V2** הוא כלי CLI מתקדם שנבנה עבור בודקי חדירה (Pentesters) ואנשי אבטחת מידע לביצוע ביקורות אבטחה ברשתות אלחוטיות בסביבת מעבדה. הכלי מבצע אוטומציה מלאה לתהליכי סריקה, ניתוק (Deauthentication), לכידת Handshake ופיצוח סיסמאות.

---

## 🛡️ אזהרת שימוש (Disclaimer) - חשוב מאוד!
**השימוש בכלי זה נועד למטרות לימודיות ומחקר בלבד בסביבת מעבדה מבוקרת.** אין להשתמש בכלי זה על רשתות שאינן בבעלותך או שאין לך אישור מפורש בכתב לבדוק אותן. שימוש לרעה בכלי זה עלול להוות עבירה פלילית על פי חוק המחשבים. המפתח (Rotem Zacaim) אינו אחראי לכל נזק או שימוש בלתי חוקי שייעשה בתוכנה זו.

---

## 🚀 יכולות מרכזיות (Core Features)

### 1. ניהול ממשקי רשת (Interface Management)
* זיהוי אוטומטי של כרטיסי רשת אלחוטיים תומכים.
* מעבר מהיר למצב ניטור (Monitor Mode) וחזרה למצב Managed.
* איפוס שירותי רשת (NetworkManager) למניעת התנגשויות.

### 2. סריקה אקטיבית ופסיבית (Scanning)
* סריקת רשתות בזמן אמת והצגת נתונים קריטיים: BSSID, Channel, Encryption, Power (RSSI).
* סידור וסינון רשתות לפי עוצמת אות לזיהוי מטרות קרובות.

### 3. מנגנון תקיפה (Attack Engine)
* **Deauth Attack:** שליחת חבילות ניתוק מסיביות לניתוק משתמשים וזיהוי לקוחות מחוברים.
* **Targeted Capture:** האזנה ממוקדת לערוץ המטרה ללכידת WPA/WPA2 4-Way Handshake.
* **Automated Cracking:** חיבור מובנה ל-`Aircrack-ng` לפיצוח קבצי לכידה מול מילוני סיסמאות (Wordlists).

### 4. ניהול סשנים (Session & Reports)
* שמירה אוטומטית של כל הלוגים והלכידות תחת תיקיית סשן ייחודית בנתיב: `~/.zacaim_v2/sessions/`.
* ייצוא דוחות בפורמט JSON ו-TXT לתיעוד הממצאים.

---

## 🛠️ דרישות מערכת (Requirements)
הכלי נבנה עבור **Kali Linux** ודורש את הכלים הבאים מותקנים:
* `Aircrack-ng Suite` (airodump, aireplay, airmon)
* `Python 3.x`
* `Sudo` (הרשאות Root נדרשות לגישה לחומרה)

---

## 📦 התקנה והרצה (Installation)

```bash
# שיבוט הריפו
git clone [https://github.com/YourUsername/Zacaim-WiFi-Tool.git](https://github.com/YourUsername/Zacaim-WiFi-Tool.git)
cd Zacaim-WiFi-Tool

# התקנת ספריות עיצוב (אופציונלי)
pip3 install rich inquirer

# הרצת הכלי
sudo python3 zacaim_wifi_tool.py
