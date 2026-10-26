<?php
// Seed a MySQL-backed, entirely invented Coursera-style registry for demos.
// Safe to re-run: only this demo table's rows and managed source are replaced.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit('CLI only.'); }
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

try {
    $db = Database::getInstance();
    $db->exec('CREATE TABLE IF NOT EXISTS demo_mooc_registry (
        certificate_id VARCHAR(64) PRIMARY KEY, holder VARCHAR(160) NOT NULL,
        title VARCHAR(200) NOT NULL, issuer VARCHAR(120) NOT NULL,
        issue_date DATE NOT NULL, status VARCHAR(20) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $records = [
        ['DEMO-MOOC-001','Asha Menon','Python Data Analysis','Coursera Learning Network','2024-01-18','active'],
        ['DEMO-MOOC-002','Mateo Ruiz','Foundations of Project Management','Coursera Learning Network','2024-02-22','active'],
        ['DEMO-MOOC-003','Nadia Ibrahim','Introduction to Cloud Computing','Open Skills Academy','2024-03-05','active'],
        ['DEMO-MOOC-004','Ethan Brooks','UX Research and Design','Open Skills Academy','2024-04-12','active'],
        ['DEMO-MOOC-005','Linh Tran','Machine Learning Essentials','Coursera Learning Network','2024-05-09','revoked'],
        ['DEMO-MOOC-006','Samira Patel','Cybersecurity Fundamentals','Digital Learning Institute','2024-06-14','active'],
        ['DEMO-MOOC-007','Noah Kim','Business Writing','Digital Learning Institute','2024-07-01','active'],
        ['DEMO-MOOC-008','Isabel Costa','SQL for Data Reporting','Coursera Learning Network','2024-08-16','active'],
        ['DEMO-MOOC-009','Omar Hassan','Sustainable Cities','Open Skills Academy','2024-09-23','active'],
        ['DEMO-MOOC-010','Zoe Williams','Digital Marketing Analytics','Digital Learning Institute','2024-10-30','active'],
    ];
    $db->beginTransaction();
    $db->exec('DELETE FROM demo_mooc_registry');
    $stmt = $db->prepare('INSERT INTO demo_mooc_registry (certificate_id,holder,title,issuer,issue_date,status) VALUES (:id,:holder,:title,:issuer,:date,:status)');
    foreach ($records as $r) $stmt->execute(['id'=>$r[0],'holder'=>$r[1],'title'=>$r[2],'issuer'=>$r[3],'date'=>$r[4],'status'=>$r[5]]);

    $cfg = [
        'dsn' => 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
        'user' => DB_USER, 'pass' => DB_PASS, 'table' => 'demo_mooc_registry',
        'cols' => ['id'=>'certificate_id','holder'=>'holder','title'=>'title','issuer'=>'issuer','date'=>'issue_date','status'=>'status'],
    ];
    $encrypted = CryptoService::encryptConfig(json_encode($cfg, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    $upsert = $db->prepare("INSERT INTO external_sources (slug,label,type,config_json,enabled,allowed_host,rate_limit)
        VALUES ('demo-mooc','DEMO MOOC registry','remote_db',:cfg,1,'localhost',30)
        ON DUPLICATE KEY UPDATE label=VALUES(label),type=VALUES(type),config_json=VALUES(config_json),enabled=1,allowed_host='localhost',rate_limit=30");
    $upsert->execute(['cfg'=>$encrypted]);
    $db->commit();
    echo "Seeded 10 invented Coursera-style records and enabled the DEMO MOOC registry source.\n";
    echo "Look up DEMO-MOOC-001 through DEMO-MOOC-010 after applying migration 010 and setting EXT_REGISTRY_ENABLED=true.\n";
} catch (Throwable $e) {
    if (isset($db) && $db->inTransaction()) $db->rollBack();
    fwrite(STDERR, "Seed failed. Check database connectivity and apply migration 010.\n");
    error_log('[CertiVault] demo source seed failed: ' . $e->getMessage());
    exit(1);
}
