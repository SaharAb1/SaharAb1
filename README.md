- 👋 Hi, I’m @SaharAb1
- 👀 I’m interested in cyber security and network structure
- happy to be here
מנהלים לרוב מתעניינים בנתונים שנותנים תמונה כוללת על מצב הארגון, יכולות ההגנה, זמני תגובה, ותובנות על התקפות פוטנציאליות. הנה שאילתות KQL נוספות שמתרכזות בהיבטים אופרטיביים וסוגי מתקפות:

1. פילוח מתקפות לפי סוג ומידת חומרה

CloudSecurityEvents
| summarize EventCount = count() by AttackType, Severity
| order by EventCount desc

שאילתה זו מחזירה פילוח של סוגי מתקפות (למשל, Brute Force, Phishing, Data Exfiltration) ורמות החומרה שלהן.

2. מתקפות לפי אזורים גיאוגרפיים

CloudSecurityEvents
| summarize EventCount = count() by GeoLocation, AttackType
| order by EventCount desc

שאילתה זו מחזירה את כמות המתקפות לפי מיקום גיאוגרפי (מדינות) וסוג המתקפה.

3. זיהוי משתמשים עם כמות אירועים חשודים גבוהה

UserActivityLogs
| where ActivityType == 'SuspiciousLogin' or ActivityType == 'UnauthorizedAccess'
| summarize SuspiciousEvents = count() by UserId
| top 10 by SuspiciousEvents

שאילתה זו מזהה את המשתמשים עם כמות האירועים החשודים הגבוהה ביותר, כמו ניסיונות גישה לא מורשים.

4. כמות התקפות מבוססות רשת לפי סוגי פורטים

NetworkSecurityLogs
| summarize PortAttackCount = count() by Port, Protocol, AttackType
| order by PortAttackCount desc

שאילתה זו מנתחת התקפות רשת (כמו Port Scanning) לפי פורטים ופרוטוקולים.

5. פילוח מתקפות לפי ספק שירות ענן (AWS, Azure, GCP)

CloudSecurityEvents
| summarize EventCount = count() by Platform, AttackType
| order by EventCount desc

שאילתה זו נותנת תובנות על כמות וסוג המתקפות לפי ספק שירותי הענן.

6. מעקב אחרי אירועים שהובילו לדליפת נתונים

CloudDataEvents
| where EventType == 'DataLeak' or EventType == 'UnauthorizedDownload'
| summarize DataLeakCount = count(), TotalDataLeaked = sum(DataSizeInMB) by Platform
| order by DataLeakCount desc

שאילתה זו עוקבת אחרי אירועים שגרמו לדליפת נתונים וכמות הנתונים שנחשפו לפי פלטפורמה.

7. סטטוס עדכוני אבטחה על שירותים מרכזיים

CloudServiceUpdates
| where UpdateType == 'SecurityPatch'
| summarize PatchCount = count() by Platform, ServiceName, PatchStatus
| order by PatchCount desc

שאילתה זו מציגה את סטטוס עדכוני האבטחה לשירותים קריטיים בכל ענן.

8. זמני תגובה ממוצעים לאירועים לפי סוג

CloudIncidentResponse
| summarize AvgResponseTime = avg(ResponseTimeInSeconds) by IncidentType
| order by AvgResponseTime asc

שאילתה זו מראה את זמני התגובה הממוצעים לאירועים, מפולחים לפי סוג.

9. אירועים של התחזות וגניבת זהות (Identity Theft)

IdentityProtectionLogs
| where EventType == 'ImpersonationAttempt' or EventType == 'IdentityTheft'
| summarize EventCount = count() by Platform, bin(Timestamp, 1d)
| order by EventCount desc

שאילתה זו עוקבת אחרי אירועים של גניבת זהות וניסיונות התחזות לפי פלטפורמה.

10. אינדיקציה לפעילות פנימית חריגה (Insider Threats)

UserBehaviorAnalytics
| where BehaviorAnomalyScore > 80
| summarize AnomaliesCount = count() by UserId, Department
| top 10 by AnomaliesCount

שאילתה זו מזהה משתמשים עם פעילות חריגה, מסוכנת או חריגה מהרגיל לפי ניקוד.

11. מתקפות אוטומטיות שזוהו ונחסמו בזמן אמת

AutomationSecurityLogs
| where AutomationAction == 'Blocked' and ThreatType == 'AutomatedAttack'
| summarize BlockedCount = count() by Platform, ThreatType
| order by BlockedCount desc

שאילתה זו מציגה את כמות ההתקפות האוטומטיות שנחסמו בזמן אמת לפי פלטפורמה וסוג המתקפה.

12. כמות אירועים לפי ספק צד שלישי בשירותי ענן

ThirdPartyServiceLogs
| summarize EventCount = count() by ProviderName, IncidentSeverity
| order by EventCount desc

שאילתה זו מנתחת אירועים שמגיעים משירותי צד שלישי המחוברים לסביבת הענן.

הנתונים האלה מתאימים מאוד לדיווחים למנהלים, ומאפשרים ניתוח איכותי וכמותי של מצב ההגנה הארגונית בענן.
