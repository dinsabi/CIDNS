<?php
session_start();

// ---- Language handling ----------------------------------------------------
$supported = ['en','fr','nl'];
if (isset($_GET['lang']) && in_array($_GET['lang'], $supported, true)) {
  $_SESSION['lang'] = $_GET['lang'];
}
$lang = $_SESSION['lang'] ?? 'en';

// ---- Default country per language ----------------------------------------
$langDefaultCountry = [
  'fr' => 'FR', // France
  'nl' => 'BE', // Belgique Neerlandophone
  'fr' => 'BE', // Belgique Francophone
  'en' => 'BE', // Belgium (par défaut)
];
$defaultCountry = $langDefaultCountry[$lang] ?? 'BE';

// ---- CSRF token for the contact form -------------------------------------
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf'];

// ---- Helpers --------------------------------------------------------------
function e($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function digits_only($s){ return preg_replace('/\D+/', '', $s ?? ''); }

// ---- SMS (Twilio) ---------------------------------------------------------
function send_sms_twilio($toE164, $message){
  $sid   = getenv('TWILIO_SID') ?: '';
  $token = getenv('TWILIO_TOKEN') ?: '';
  $from  = getenv('TWILIO_FROM') ?: '';
  if ($sid==='' || $token==='' || $from==='') {
    @file_put_contents(__DIR__.'/sms_fallback.log', date('c')."\tNO_TWILIO\t{$toE164}\t".str_replace(["\r","\n"],' ',$message)."\n", FILE_APPEND);
    return false;
  }
  $url  = "https://api.twilio.com/2010-04-01/Accounts/{$sid}/Messages.json";
  $post = http_build_query(['To'=>$toE164,'From'=>$from,'Body'=>$message]);
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $post,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_USERPWD => $sid.':'.$token,
    CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
    CURLOPT_TIMEOUT => 15
  ]);
  $resp = curl_exec($ch);
  $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $err  = curl_error($ch);
  curl_close($ch);
  if ($http>=200 && $http<300) return true;
  @file_put_contents(__DIR__.'/sms_fallback.log', date('c')."\tERR_HTTP{$http}\t{$toE164}\t{$err}\t".substr((string)$resp,0,500)."\n", FILE_APPEND);
  return false;
}

// ---- Minimal server fallback for dial prefixes ---------------------------
$serverFallbackPrefixes = ['BE'=>'+32','FR'=>'+33','NL'=>'+31','DE'=>'+49','LU'=>'+352'];

// ---- Form handling --------------------------------------------------------
$formStatus = null; // 'ok' | 'error'
$formErrors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Basic CSRF check
  if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
    $formErrors[] = 'Invalid request. Please try again.';
  }

  // Inputs
  $name     = trim($_POST['name'] ?? '');
  $emailRaw = trim($_POST['email'] ?? '');
  $country  = strtoupper(trim($_POST['country'] ?? $defaultCountry));
  $pfxIn    = trim($_POST['phone_prefix'] ?? '');
  $localIn  = trim($_POST['phone_local'] ?? '');
  $address  = trim($_POST['address'] ?? '');
  $postal   = trim($_POST['postal'] ?? '');
  $city     = trim($_POST['city'] ?? '');
  $message  = trim($_POST['message'] ?? '');

  // Email sanitize/validate + header injection guard
  $email_sanitized = filter_var($emailRaw, FILTER_SANITIZE_EMAIL);
  $email_valid     = filter_var($email_sanitized, FILTER_VALIDATE_EMAIL);

  $name = str_replace(["\r","\n"], ' ', $name);

  // Build E.164 phone (if user provided local number)
  $digitsPrefix = digits_only($pfxIn);
  if ($digitsPrefix==='') { $digitsPrefix = digits_only($serverFallbackPrefixes[$country] ?? ''); }
  $digitsLocal  = digits_only($localIn);
  $phone_e164   = '';
  if ($digitsLocal !== '') {
    $digitsLocal = ltrim($digitsLocal, '0');        // remove leading 0 for E.164
    if ($digitsPrefix !== '') $phone_e164 = '+'.$digitsPrefix.$digitsLocal;
  }

  // Validation
  if ($name === '') { $formErrors[] = 'Name is required.'; }
  if (!$email_valid) { $formErrors[] = 'A valid email is required.'; }
  if ($message === '') { $formErrors[] = 'Message is required.'; }
  if ($localIn !== '' && !preg_match('/^\+\d{6,15}$/', $phone_e164)) {
    $formErrors[] = 'Phone number format is not valid.';
  }

  if (!$formErrors) {
    // Prepare email to CIDNS
    $to       = 'dieudonne.nsabimana@cidns.eu, info@cidns.eu';
    $subject  = 'New contact form submission (cidns.eu)';
    $body     =
      "Name: {$name}\n"
      . "Email: {$email_sanitized}\n"
      . "Country: {$country}\n"
      . "Phone (E.164): " . ($phone_e164 ?: 'N/A') . "\n"
      . "Address: {$address}\n"
      . "Postal code: {$postal}\n"
      . "City: {$city}\n\n"
      . "Message:\n{$message}\n";

    $headersArr = [
      'From' => 'no-reply@cidns.eu',
      'Reply-To' => $email_sanitized,
      'Content-Type' => 'text/plain; charset=UTF-8'
    ];
    $headersStr = '';
    foreach ($headersArr as $k => $v) { $headersStr .= $k . ': ' . $v . "\r\n"; }

    // Prepare copy to the client (acknowledgement)
    $copySubject = ($lang === 'fr')
      ? 'Accusé de réception - CIDNS'
      : (($lang === 'nl') ? 'Ontvangstbevestiging - CIDNS' : 'Receipt confirmation - CIDNS');

    $copyIntro = [
      'en' => "Hello {$name},\n\nWe have received your message. Our team will get back to you soon.\n\nHere is a copy for your records:\n\n",
      'fr' => "Bonjour {$name},\n\nNous avons bien reçu votre message. Notre équipe vous répondra rapidement.\n\nCopie pour vos archives :\n\n",
      'nl' => "Hallo {$name},\n\nWe hebben uw bericht ontvangen. Ons team neemt spoedig contact met u op.\n\nKopie voor uw archief:\n\n",
    ][$lang] ?? "Hello {$name},\n\nWe have received your message. Our team will get back to you soon.\n\nHere is a copy for your records:\n\n";

    $copyBody = $copyIntro . $body;

    $copyHeadersArr = [
      'From' => 'no-reply@cidns.eu',
      'Reply-To' => 'info@cidns.eu',
      'Content-Type' => 'text/plain; charset=UTF-8'
    ];
    $copyHeadersStr = '';
    foreach ($copyHeadersArr as $k => $v) { $copyHeadersStr .= $k . ': ' . $v . "\r\n"; }

    // Attempt to send both emails
    $sentCidns = @mail($to, $subject, $body, $headersStr);
    $sentCopy  = @mail($email_sanitized, $copySubject, $copyBody, $copyHeadersStr);

    // Optional SMS ack (best effort)
    if ($phone_e164 !== '') {
      $smsMsg = [
        'en' => "CIDNS: we received your message. We'll get back to you soon. Ref ".date('YmdHis'),
        'fr' => "CIDNS : nous avons bien reçu votre message. Réf ".date('YmdHis'),
        'nl' => "CIDNS: we hebben uw bericht ontvangen. Ref ".date('YmdHis'),
      ][$lang] ?? "CIDNS: we received your message. Ref ".date('YmdHis');
      send_sms_twilio($phone_e164, $smsMsg);
    }

    if ($sentCidns) {
      $formStatus = 'ok';
      // Regenerate CSRF after successful post to prevent resubmission
      $_SESSION['csrf'] = bin2hex(random_bytes(32));
      $csrfToken = $_SESSION['csrf'];
      // Clear POST values to avoid refilling form after success
      $_POST = [];
    } else {
      // Fallback: write to local log so no message is lost
      $logLine = date('c')
        . "\t{$name}\t{$email_sanitized}\t{$country}\t{$phone_e164}\t{$address}\t{$postal}\t{$city}\t"
        . str_replace(["\r","\n"],' ', $message) . "\n";
      @file_put_contents(__DIR__ . '/contact_fallback.log', $logLine, FILE_APPEND);
      $formStatus = 'error';
      $formErrors[] = 'We could not send the email automatically. Your message was saved and our team will review it.';
    }
  } else {
    $formStatus = 'error';
  }
}

// ---- Translations (EN, FR, NL fully populated) ----------------------------
$t = [
  'en' => [
    'meta_desc' => 'CIDNS - IT Consulting Company',
    'title' => 'CIDNS - IT Consulting',
    'nav' => ['Overview','Services & Products','Why Us','Contact','Partners'],
    'hero' => 'Your partner for a <span class="highlight">secure and agile</span> cloud',
    'overview_h' => 'Overview',
    'overview_p1' => 'Consulting company founded in February 2025, specialized in cybersecurity.',
    'overview_p2' => 'CIDNS is a privately held provider of professional IT services. We rely on highly qualified and motivated teams of IT professionals, serving a well-established and satisfied customer base. Our working culture is built around continuously meeting the technical, quality, budgetary, and timing constraints set by our customers.',
    'overview_p3' => 'At <strong>CIDNS</strong>, we support your <strong>digital transformation</strong> with expert, secure, and business-focused cloud migration solutions. Our mission is simple: ensure a <strong>successful cloud migration</strong>—from initial audit to production—while guaranteeing performance, security, and compliance.',
    'services_h' => 'Services & Products',
    'learn_more' => 'Learn more',
    'labels' => [ 'new' => 'NEW' ],
    'nis2' => [
      'badge'  => 'Offer of the month',
      'h'      => 'NIS2 Compliance & Readiness',
      'sub'    => 'End-to-end support to meet EU NIS2 cybersecurity obligations.',
      'points' => [
        'Gap assessment & prioritized roadmap',
        'Policies & governance (ISO 27001 alignment)',
        '72h incident reporting playbooks',
        'Third-party & supply-chain risk management',
        'vCISO & continuous compliance monitoring'
      ],
      'cta'   => 'Explore our NIS2 service',
      'href'  => 'nis2-compliance.php'
    ],
    'services' => [
      ['Initial Audit & Existing System Analysis', ['Identify existing infrastructure, applications, and processes', 'Evaluate business needs, technical and regulatory constraints'], 'initial-audit-analysis.html'],
      ['Needs Definition & Scoping', ['Gather client expectations','Define migration goals, priorities, and KPIs'], 'needs_scoping_page.html'],
      ['Target Architecture Design', ['Create cloud architecture (AWS, Azure, GCP, or hybrid)','Select technologies: Kubernetes, OpenShift, IaaS/PaaS/SaaS','Optimize costs and performance'], 'target-architecture-design.html'],
      ['Cloud Provider Selection & Governance', ['Assist in cloud provider selection','Implement IT governance: security, compliance, supervision'], 'cloud-governance-page.html'],
      ['Agile Project Management & Steering', ['Agile methodology (Scrum, Kanban)','Track deliverables, coordinate stakeholders'], 'agile-project-management-steering.html'],
      ['Delivery and Operations', ['Deliver according to quality, timeline, and budget','Provide documentation, handover, and support'], '#'],
      ['Managed Security Services (MSS)', ['24/7 monitoring','SIEM integration','Endpoint and firewall management','Monthly compliance reporting'], '#'],
      ['Virtual CISO (vCISO)', ['On-demand security leadership','GDPR/ISO/NIS2 compliance','Risk management','Board reporting'], '#'],
      ['Managed SOC Services', ['Fully managed Security Operations Center','Log collection and correlation','Continuous threat detection'], '#'],
      ['Incident Response & Forensics', ['Immediate containment','Digital forensics','GDPR-compliant notification','Recovery planning and hardening recommendations'], '#'],
      ['Penetration Testing & Red Teaming', ['Network and application tests','Realistic simulations','Mitigation recommendations'], '#'],
      ['Security Assessments & Compliance Audits', ['GDPR, NIS2, ISO 27001 evaluations','Gap analysis','Certification readiness support'], '#'],
      ['Security Awareness Training', ['Phishing simulations','Sector-specific modules','Compliance tracking'], '#'],
      ['Vulnerability Management', ['Regular scans','CVSS prioritization','ITSM integration','Continuous monitoring'], '#'],
      ['Threat Intelligence Services', ['Regional threat intelligence','Actor profiles','Real-time alerts','MITRE ATT&CK integration'], '#']
    ],
    'whyus_h' => 'Why Us',
    'whyus_list' => ['EU-based infrastructure','Strong alignment with European cybersecurity laws','Multilingual teams','Proven expertise in public and private sectors'],
    'contact_h' => 'Contact',
    'email' => 'Email',
    'phone' => 'Phone',
    'form_name' => 'Your Name',
    'form_email' => 'Your Email',
    'form_country' => 'Country',
    'form_phone_prefix' => 'Prefix',
    'form_phone_local' => 'Local number',
    'form_address' => 'Your Address',
    'form_postal' => 'Postal code',
    'form_city' => 'City',
    'form_message' => 'Your Message',
    'form_send' => 'Send',
    'form_success' => 'Thank you for your message! We will get back to you soon.',
    'partners_h' => 'Partners',
    'footer' => '© 2025 CIDNS. All rights reserved.'
  ],
  'fr' => [
    'meta_desc' => 'CIDNS - Société de conseil en informatique',
    'title' => 'CIDNS - Conseil en IT',
    'nav' => ['Aperçu','Services & Produits','Pourquoi nous','Contact','Partenaires'],
    'hero' => 'Votre partenaire pour un cloud <span class="highlight">sécurisé et agile</span>',
    'overview_h' => 'Aperçu',
    'overview_p1' => 'Société de consultance fondée en février 2025, spécialisée en cybersécurité.',
    'overview_p2' => 'CIDNS est une société privée fournissant des services IT professionnels. Nous nous appuyons sur des équipes hautement qualifiées et motivées, au service d\'une clientèle fidèle et satisfaite. Notre culture de travail repose sur la satisfaction continue des exigences techniques, qualitatives, budgétaires et de délais fixées par nos clients.',
    'overview_p3' => 'Chez <strong>CIDNS</strong>, nous accompagnons votre <strong>transformation numérique</strong> avec des solutions de migration cloud expertes, sécurisées et orientées métier. Notre mission est simple : assurer une <strong>migration cloud réussie</strong> — de l\'audit initial à la production — tout en garantissant performance, sécurité et conformité.',
    'services_h' => 'Services & Produits',
    'learn_more' => 'En savoir plus',
    'labels' => [ 'new' => 'Nouveauté' ],
    'nis2' => [
      'badge'  => 'Offre du mois',
      'h'      => 'Conformité & Préparation NIS2',
      'sub'    => 'Accompagnement de bout en bout pour répondre aux obligations NIS2 dans l’UE.',
      'points' => [
        'État des lieux & feuille de route priorisée',
        'Politiques & gouvernance (alignement ISO 27001)',
        'Playbooks de notification d’incident sous 72h',
        'Gestion des risques tiers / chaîne d’approvisionnement',
        'vCISO & conformité continue'
      ],
      'cta'   => 'Découvrir notre service NIS2',
      'href'  => 'nis2-compliance.php'
    ],
    'services' => [
      ['Audit initial & Analyse de l’existant', ['Cartographier les infrastructures, applications et processus', 'Évaluer les besoins métiers et contraintes techniques/réglementaires'], 'initial-audit-analysis.html'],
      ['Définition des besoins & Cadrage', ['Collecte des attentes','Définition des objectifs, priorités et KPIs'], 'needs_scoping_page.html'],
      ['Conception d’architecture cible', ['Architecture cloud (AWS, Azure, GCP ou hybride)','Choix technos : Kubernetes, OpenShift, IaaS/PaaS/SaaS','Optimisation coûts & performances'], 'target-architecture-design.html'],
      ['Choix du fournisseur & Gouvernance', ['Aide au choix du cloud','Mise en place de la gouvernance IT : sécurité, conformité, supervision'], 'cloud-governance-page.html'],
      ['Pilotage & gestion de projet agile', ['Méthodologies agiles (Scrum, Kanban)','Suivi des livrables, coordination parties prenantes'], 'agile-project-management-steering.html'],
      ['Delivery & Opérations', ['Livraison selon qualité, délais, budget','Documentation, transfert et support'], '#'],
      ['Managed Security Services (MSS)', ['Supervision 24/7','Intégration SIEM','Gestion endpoints & firewall','Rapports mensuels de conformité'], '#'],
      ['vCISO (CISO virtuel)', ['Leadership sécurité à la demande','Conformité RGPD/ISO/NIS2','Gestion des risques','Reporting au board'], '#'],
      ['SOC managé', ['Centre Opérationnel de Sécurité managé','Collecte et corrélation des logs','Détection continue des menaces'], '#'],
      ['Réponse à incident & Forensic', ['Confinement immédiat','Forensique numérique','Notification RGPD conforme','Plan de reprise & recommandations de durcissement'], '#'],
      ['Tests d’intrusion & Red Team', ['Tests réseau & applicatif','Simulations réalistes','Recommandations de remédiation'], '#'],
      ['Évaluations sécurité & Audits conformité', ['Évaluations RGPD, NIS2, ISO 27001','Gap analysis','Préparation à la certification'], '#'],
      ['Sensibilisation sécurité', ['Campagnes phishing','Modules sectoriels','Suivi de conformité'], '#'],
      ['Gestion des vulnérabilités', ['Scans réguliers','Priorisation CVSS','Intégration ITSM','Surveillance continue'], '#'],
      ['Threat Intelligence', ['Veille régionale','Profils d’acteurs','Alertes en temps réel','Intégration MITRE ATT&CK'], '#']
    ],
    'whyus_h' => 'Pourquoi nous',
    'whyus_list' => ['Infrastructure basée dans l’UE','Alignement fort avec les lois européennes de cybersécurité','Équipes multilingues','Expertise avérée secteur public & privé'],
    'contact_h' => 'Contact',
    'email' => 'Email',
    'phone' => 'Téléphone',
    'form_name' => 'Votre nom',
    'form_email' => 'Votre e-mail',
    'form_country' => 'Pays',
    'form_phone_prefix' => 'Préfixe',
    'form_phone_local' => 'Numéro local',
    'form_address' => 'Votre adresse',
    'form_postal' => 'Code postal',
    'form_city' => 'Commune',
    'form_message' => 'Votre message',
    'form_send' => 'Envoyer',
    'form_success' => 'Merci pour votre message ! Nous vous répondrons rapidement.',
    'partners_h' => 'Partenaires',
    'footer' => '© 2025 CIDNS. Tous droits réservés.'
  ],
  'nl' => [
    'meta_desc' => 'CIDNS - IT-adviesbureau',
    'title' => 'CIDNS - IT Consulting',
    'nav' => ['Overzicht','Diensten & Producten','Waarom wij','Contact','Partners'],
    'hero' => 'Uw partner voor een <span class="highlight">veilige en flexibele</span> cloud',
    'overview_h' => 'Overzicht',
    'overview_p1' => 'Consultancybedrijf opgericht in februari 2025, gespecialiseerd in cyberbeveiliging.',
    'overview_p2' => 'CIDNS is een particuliere aanbieder van professionele IT-diensten. We rekenen op hooggekwalificeerde en gemotiveerde teams die een trouwe en tevreden klantenbasis bedienen. Onze werkcultuur is gericht op het consequent voldoen aan de technische, kwaliteits-, budgettaire en tijdsvereisten van onze klanten.',
    'overview_p3' => 'Bij <strong>CIDNS</strong> ondersteunen we uw <strong>digitale transformatie</strong> met deskundige, veilige en bedrijfsgerichte cloudmigratieoplossingen. Onze missie is eenvoudig: zorgen voor een <strong>succesvolle cloudmigratie</strong>—van initiële audit tot productie—met gegarandeerde prestaties, beveiliging en compliance.',
    'services_h' => 'Diensten & Producten',
    'learn_more' => 'Meer weten',
    'labels' => [ 'new' => 'NIEUW' ],
    'nis2' => [
      'badge'  => 'Maandaanbieding',
      'h'      => 'NIS2 Compliance & Voorbereiding',
      'sub'    => 'End-to-end ondersteuning voor naleving van EU NIS2-verplichtingen.',
      'points' => [
        'Gap-analyse & geprioriteerde roadmap',
        'Beleid & governance (ISO 27001-afstemming)',
        '72u incident-meldingsplaybooks',
        'Risicobeheer derde partijen / supply chain',
        'vCISO & continue compliance'
      ],
      'cta'   => 'Ontdek onze NIS2-dienst',
      'href'  => 'nis2-compliance.php'
    ],
    'services' => [
      ['Initiële audit & analyse', ['Bestaande infrastructuur, apps en processen in kaart brengen', 'Behoeften en technische/regulatoire beperkingen evalueren'], 'initial-audit-analysis.html'],
      ['Behoeftenbepaling & scoping', ['Verwachtingen verzamelen','Doelen, prioriteiten en KPI’s bepalen'], 'needs_scoping_page.html'],
      ['Doelarchitectuur ontwerpen', ['Cloudarchitectuur (AWS, Azure, GCP of hybride)','Technologiekeuze: Kubernetes, OpenShift, IaaS/PaaS/SaaS','Kosten- en prestatieoptimalisatie'], 'target-architecture-design.html'],
      ['Cloudkeuze & governance', ['Begeleiding bij cloudselectie','IT-governance: security, compliance, supervisie implementeren'], 'cloud-governance-page.html'],
      ['Agile projectsturing', ['Agile methodes (Scrum, Kanban)','Deliverables opvolgen, stakeholders afstemmen'], 'agile-project-management-steering.html'],
      ['Levering & Operaties', ['Leveren volgens kwaliteit, timing en budget','Documentatie, overdracht en support'], '#'],
      ['Managed Security Services (MSS)', ['24/7 monitoring','SIEM-integratie','Endpoint- en firewallbeheer','Maandelijkse compliancerapporten'], '#'],
      ['Virtuele CISO (vCISO)', ['Security leadership on-demand','GDPR/ISO/NIS2-compliance','Risicobeheer','Rapportering aan het bestuur'], '#'],
      ['Managed SOC', ['Volledig beheerd Security Operations Center','Logverzameling en correlatie','Continue dreigingsdetectie'], '#'],
      ['Incidentrespons & Forensics', ['Onmiddellijke indamming','Digitale forensica','GDPR-conforme melding','Herstelplan en hardening-adviezen'], '#'],
      ['Pen-tests & Red Teaming', ['Netwerk- en applicatietests','Realistische simulaties','Mitigatie-aanbevelingen'], '#'],
      ['Security assessments & compliance-audits', ['GDPR, NIS2, ISO 27001 evaluaties','Gap-analyse','Begeleiding naar certificering'], '#'],
      ['Security awareness training', ['Phishing-simulaties','Sectorspecifieke modules','Compliance-tracking'], '#'],
      ['Kwetsbaarheidsbeheer', ['Regelmatige scans','CVSS-prioritering','ITSM-integratie','Continue monitoring'], '#'],
      ['Threat Intelligence', ['Regionale dreigingsinformatie','Acteursprofielen','Realtime alerts','MITRE ATT&CK-integratie'], '#']
    ],
    'whyus_h' => 'Waarom wij',
    'whyus_list' => ['EU-gebaseerde infrastructuur','Sterke afstemming op Europese cyberwetten','Meertalige teams','Bewezen expertise in publieke & private sector'],
    'contact_h' => 'Contact',
    'email' => 'E-mail',
    'phone' => 'Telefoon',
    'form_name' => 'Uw naam',
    'form_email' => 'Uw e-mailadres',
    'form_country' => 'Land',
    'form_phone_prefix' => 'Prefix',
    'form_phone_local' => 'Lokaal nummer',
    'form_address' => 'Uw adres',
    'form_postal' => 'Postcode',
    'form_city' => 'Gemeente',
    'form_message' => 'Uw bericht',
    'form_send' => 'Verzenden',
    'form_success' => 'Bedankt voor uw bericht! We nemen snel contact met u op.',
    'partners_h' => 'Partners',
    'footer' => '© 2025 CIDNS. Alle rechten voorbehouden.'
  ]
];

// Inject NIS2 card as the first service card
$nis2 = $t[$lang]['nis2'];
array_unshift($t[$lang]['services'], [ $nis2['h'], $nis2['points'], $nis2['href'] ]);
?>
<!DOCTYPE html>
<html lang="<?= e($lang) ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="<?= e($t[$lang]['meta_desc']) ?>">
  <title><?= e($t[$lang]['title']) ?></title>

  <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&display=swap" rel="stylesheet">
  <style>
    :root { --primary-color:#0D1B2A; --secondary-color:#1B263B; --accent-color:#4DA3FF; --light-color:#F1FAEE; }
    *{box-sizing:border-box}
    body{margin:0;font-family:'Poppins',sans-serif;background:linear-gradient(to bottom right,#1B263B,#0D1B2A);color:var(--light-color);line-height:1.6}
    header{background-image:url('images/ruban_sc.jpeg');background-size:cover;background-position:center;padding:40px 20px;display:flex;align-items:center;gap:20px;box-shadow:0 6px 12px rgba(0,0,0,.6)}
    header a.logo-link img{max-height:100px;animation:fadeIn 1.5s ease-in-out;display:block}
    header .header-text{display:flex;flex-direction:column;font-size:1.2em;color:white}
    header .header-text h1{color:white;font-size:clamp(1.2rem, 2.5vw, 2rem);margin:0;text-align:left}

    nav{position:sticky;top:0;z-index:1000;display:flex;justify-content:space-between;align-items:center;background:var(--secondary-color);padding:10px 20px;box-shadow:0 2px 6px rgba(0,0,0,.6)}
    .nav-links{display:flex;align-items:center;gap:20px}
    nav a{color:var(--light-color);text-decoration:none;font-weight:700;position:relative;transition:color .3s}
    nav a::after{content:'';position:absolute;width:0;height:3px;bottom:-5px;left:0;background:var(--accent-color);transition:width .3s}
    nav a:hover::after, nav a[aria-current="page"]::after{width:100%}
    .lang-switch{display:flex;gap:6px}
    .lang-switch a{padding:4px 8px;font-size:.8em;border:none;border-radius:4px;cursor:pointer;font-weight:bold;background:#fff;color:var(--primary-color);text-decoration:none}
    .lang-switch a:hover{background:var(--accent-color);color:#fff}

    .marquee-viewport{position:relative;overflow:hidden;width:100vw;margin-left:calc(50% - 50vw);height:3.6em;padding-top:0.35em;margin-top:8px;margin-bottom:10px}
    .marquee-track{position:absolute;top:0.15em;white-space:nowrap;font-size:clamp(1.6rem,3vw,2.6rem);font-family:'Great Vibes','Poppins',cursive;font-weight:400;line-height:1.1;letter-spacing:.5px;will-change:transform;animation:marqueeAcross 22s linear infinite;color:#cbe86b;background-image:linear-gradient(90deg,#27ae60,#8bc34a,#d4e157,#f4d03f);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
    @keyframes marqueeAcross{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}

    section{padding:60px 20px;max-width:1200px;margin:auto}
    h2{color:var(--accent-color);font-size:2.2em;margin-bottom:25px;border-left:6px solid var(--accent-color);padding-left:12px;text-transform:uppercase;letter-spacing:1px}

    .overview-container{display:grid;grid-template-columns:1fr 1.2fr 1.6fr;gap:28px;align-items:start;animation:fadeIn 1.2s ease-in-out}
    .overview-container img{width:100%;height:auto;border-radius:12px;box-shadow:0 8px 20px rgba(0,0,0,.6)}
    @media (max-width:1024px){ .overview-container{grid-template-columns:1fr; } }

    .nis2-bright{position:relative;background: radial-gradient(120% 140% at 0% 0%, rgba(77,163,255,.35), rgba(27,38,59,.9));border:1px solid rgba(77,163,255,.55);border-radius:16px;padding:20px 18px;box-shadow:0 0 30px rgba(77,163,255,.45),0 12px 28px rgba(0,0,0,.45), inset 0 0 18px rgba(77,163,255,.18);color:#EAF4FF;}
    .nis2-bright .badge{display:inline-block;background:#4DA3FF;color:#0D1B2A;font-weight:900;padding:4px 10px;border-radius:999px;font-size:.78rem;letter-spacing:.3px;box-shadow:0 0 10px rgba(77,163,255,.8);}
    .new-badge{display:block;font-size:1.3rem;font-style:italic;font-weight:900;margin-bottom:6px;background:linear-gradient(90deg,#2ecc71,#f1c40f);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-shadow:0 0 6px rgba(241,196,15,0.6),0 0 12px rgba(46,204,113,0.5);animation:glowPulse 2s infinite alternate;}
    @keyframes glowPulse {0% {text-shadow:0 0 6px rgba(241,196,15,0.6),0 0 12px rgba(46,204,113,0.5);}100% {text-shadow:0 0 16px rgba(241,196,15,1),0 0 24px rgba(46,204,113,0.8);}}
    .nis2-bright h3{margin:.5rem 0 .3rem 0;font-size:1.5rem}
    .nis2-bright p{margin:.25rem 0 .75rem 0;opacity:.96}
    .nis2-bright ul{margin:.4rem 0 .8rem 1.1rem}
    .nis2-bright li{margin:.25rem 0}
    .nis2-bright .cta{display:inline-block;border:2px solid #4DA3FF;border-radius:10px;padding:10px 14px;font-weight:800;text-decoration:none;color:#fff;transition:.25s;box-shadow:0 0 12px rgba(77,163,255,.55);}
    .nis2-bright .cta:hover{background:#4DA3FF;color:#0D1B2A;transform:translateY(-1px)}

    .services{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:30px}
    .service{background:var(--secondary-color);border-radius:12px;padding:25px;box-shadow:0 6px 12px rgba(0,0,0,.5);transition:transform .3s,box-shadow .3s;border-top:4px solid var(--accent-color)}
    .service:hover{transform:translateY(-6px);box-shadow:0 12px 20px rgba(0,0,0,.8)}
    .service h3{margin-top:0;color:var(--light-color);font-size:1.2em;text-align:center}
    .service ul{margin-top:12px;padding-left:22px;color:var(--light-color)}
    .service li{margin-bottom:6px}
    .service a{display:inline-block;margin-top:15px;color:var(--light-color);font-weight:600;text-decoration:none;border:2px solid var(--accent-color);padding:8px 18px;border-radius:6px;transition:all .3s ease;text-align:center}
    .service a:hover{background:var(--accent-color);color:#0D1B2A}

    .about-section{min-height:60vh;display:flex;flex-direction:column;justify-content:center;align-items:center;background:var(--primary-color);margin-top:40px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.5)}
    .about-section h2{text-align:center;border:none;font-size:2.0em;margin-bottom:20px;color:var(--accent-color)}
    .about-list{list-style-type:disc;padding-left:40px;margin-top:20px;font-size:1.1em;line-height:1.8;color:var(--light-color)}

    .contact-info{margin-top:30px;text-align:center;font-size:1.05em;line-height:1.6;color:var(--light-color)}
    form{display:flex;flex-direction:column;max-width:700px;margin:auto;background:var(--secondary-color);padding:30px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.5)}
    form input, form select, form textarea{margin-bottom:18px;padding:12px;border:1px solid #555;border-radius:6px;font-size:1em;background:#0D1B2A;color:#f5f5f5}
    form button{padding:14px;background:linear-gradient(90deg,var(--accent-color),var(--primary-color));color:white;border:none;border-radius:6px;cursor:pointer;font-weight:bold;font-size:1.1em;transition:background .3s}
    form button:hover{background:var(--accent-color);color:#0D1B2A}

    .form-row{display:flex;gap:12px}
    .form-row .col{flex:1}
    @media(max-width:520px){.form-row{flex-direction:column;gap:0}}

    footer{background:var(--secondary-color);color:white;text-align:center;padding:40px;margin-top:60px;font-size:.9em}
    .alert{max-width:700px;margin:0 auto 20px auto;padding:12px 14px;border-radius:8px}
    .alert.ok{background:#1e5f2a}
    .alert.err{background:#7a1f1f}
    @keyframes fadeIn{from{opacity:0}to{opacity:1}}
  </style>
</head>
<body>
  <header>
    <a class="logo-link" href="https://www.cidns.eu" target="_blank" rel="noopener">
      <img src="images/CIDNS-header.jpeg" alt="CIDNS company logo" loading="lazy">
    </a>
    <div class="header-text">
      <h1>CLOUD INFRASTRUCTURE DIGITAL and NETWORK SERVICES</h1>
    </div>
  </header>

  <nav aria-label="Main">
    <div class="nav-links">
      <a href="#Overview" aria-current="page"><?= e($t[$lang]['nav'][0]) ?></a>
      <a href="#services"><?= e($t[$lang]['nav'][1]) ?></a>
      <a href="#about"><?= e($t[$lang]['nav'][2]) ?></a>
      <a href="#contact"><?= e($t[$lang]['nav'][3]) ?></a>
      <a href="#Partners"><?= e($t[$lang]['nav'][4]) ?></a>
    </div>
    <div class="lang-switch" role="group" aria-label="Language switch">
      <?php foreach ($supported as $code): ?>
        <a href="?lang=<?= e($code) ?>" <?= $lang===$code? 'aria-current="true"':'' ?>><?= strtoupper($code) ?></a>
      <?php endforeach; ?>
    </div>
  </nav>

  <div class="marquee-viewport" aria-label="CIDNS tagline">
    <div class="marquee-track"><?= preg_replace('/(secure and agile Cloud|Cloud sécurisé et agile|veilige en flexibele Cloud)/i', '$1<br>', $t[$lang]['hero']) ?></div>
  </div>

  <section id="Overview">
    <div class="overview-container">
      <div><img src="images/CIDNS-header.jpeg" alt="CIDNS emblem" loading="lazy"></div>
      <div class="nis2-bright" role="complementary" aria-label="Offer of the month: NIS2">
        <em class="new-badge"><?= e($t[$lang]['labels']['new']) ?></em>
        <span class="badge"><?= e($t[$lang]['nis2']['badge']) ?></span>
        <h3><?= e($t[$lang]['nis2']['h']) ?></h3>
        <p><?= e($t[$lang]['nis2']['sub']) ?></p>
        <ul><?php foreach(($t[$lang]['nis2']['points'] ?? []) as $li): ?><li><?= e($li) ?></li><?php endforeach; ?></ul>
        <a class="cta" href="<?= e($t[$lang]['nis2']['href']) ?>?lang=<?= e($lang) ?>"><?= e($t[$lang]['nis2']['cta']) ?></a>
      </div>
      <div>
        <h2><?= e($t[$lang]['overview_h']) ?></h2>
        <p><?= $t[$lang]['overview_p1'] ?></p>
        <p><?= $t[$lang]['overview_p2'] ?></p>
        <p><?= $t[$lang]['overview_p3'] ?></p>
      </div>
    </div>
  </section>

  <section id="services">
    <h2><?= e($t[$lang]['services_h']) ?></h2>
    <div class="services">
      <?php foreach ($t[$lang]['services'] as $svc): [$title,$items,$href] = $svc; ?>
        <div class="service">
          <h3><?= e($title) ?></h3>
          <?php if (!empty($items)): ?><ul><?php foreach ($items as $li): ?><li><?= e($li) ?></li><?php endforeach; ?></ul><?php endif; ?>
          <a href="<?= e($href) ?>"><?= e($t[$lang]['learn_more']) ?></a>
        </div>
      <?php endforeach; ?>
    </div>
  </section>

  <section id="about" class="about-section">
    <h2><?= e($t[$lang]['whyus_h']) ?></h2>
    <ul class="about-list"><?php foreach ($t[$lang]['whyus_list'] as $li): ?><li><?= e($li) ?></li><?php endforeach; ?></ul>
  </section>

  <section id="Partners">
    <h2><?= e($t[$lang]['partners_h']) ?></h2>
    <p style="opacity:.9">(Coming soon) We work with cloud and security vendors across AWS, Azure, GCP, and EU-based providers.</p>
  </section>

  <section id="contact">
    <h2><?= e($t[$lang]['contact_h']) ?></h2>

    <?php if ($formStatus === 'ok'): ?>
      <div class="alert ok" role="status"><?= e($t[$lang]['form_success']) ?></div>
    <?php elseif ($formStatus === 'error'): ?>
      <div class="alert err" role="alert"><?php foreach ($formErrors as $err): ?><div><?= e($err) ?></div><?php endforeach; ?></div>
    <?php endif; ?>

    <div class="contact-info">
      <p><strong><?= e($t[$lang]['email']) ?>:</strong> <a href="mailto:info@cidns.eu" style="color:inherit">info@cidns.eu</a></p>
      <p><strong><?= e($t[$lang]['phone']) ?>:</strong> +32 495 585 914</p>
    </div>

    <!-- ================= CONTACT FORM ================= -->
    <form id="contactForm" method="POST" novalidate>
      <input type="hidden" name="csrf" value="<?= e($csrfToken) ?>">

      <input type="text"   name="name"    placeholder="<?= e($t[$lang]['form_name']) ?>"    value="<?= e($_POST['name'] ?? '') ?>" required>
      <input type="email"  name="email"   placeholder="<?= e($t[$lang]['form_email']) ?>"  value="<?= e($_POST['email'] ?? '') ?>" required>

      <!-- Country + Phone (prefix + local) -->
      <div class="form-row">
        <div class="col">
          <select name="country" id="countrySel" aria-label="<?= e($t[$lang]['form_country']) ?>"></select>
        </div>
        <div class="col">
          <input type="text" name="phone_prefix" id="phonePrefix" placeholder="<?= e($t[$lang]['form_phone_prefix']) ?>" value="<?= e($_POST['phone_prefix'] ?? '') ?>" inputmode="tel" pattern="^\+\d{1,4}$" title="+ and 1–4 digits (e.g. +32)">
        </div>
        <div class="col">
          <input type="text" name="phone_local" id="phoneLocal" placeholder="<?= e($t[$lang]['form_phone_local']) ?>" value="<?= e($_POST['phone_local'] ?? '') ?>" inputmode="tel" pattern="^[0-9\s\-\.]{6,}$" title="Local number (min 6 digits)">
        </div>
      </div>

      <input type="text"   name="address" placeholder="<?= e($t[$lang]['form_address']) ?>" value="<?= e($_POST['address'] ?? '') ?>">

      <!-- Code postal + Commune sur la même ligne -->
      <div class="form-row">
        <div class="col"><input type="text" name="postal" placeholder="<?= e($t[$lang]['form_postal']) ?>" value="<?= e($_POST['postal'] ?? '') ?>" inputmode="numeric"></div>
        <div class="col"><input type="text" name="city"   placeholder="<?= e($t[$lang]['form_city'])   ?>" value="<?= e($_POST['city'] ?? '') ?>"></div>
      </div>

      <textarea name="message" placeholder="<?= e($t[$lang]['form_message']) ?>" required><?= e($_POST['message'] ?? '') ?></textarea>
      <button type="submit"><?= e($t[$lang]['form_send']) ?></button>
    </form>
  </section>

  <footer><?= e($t[$lang]['footer']) ?></footer>

  <!-- ======= Countries + dial codes (intl-tel-input data) ======= -->
  <script>
  (function(){
    const sel = document.getElementById('countrySel');
    const phonePrefix = document.getElementById('phonePrefix');

    const postedCountry = <?= json_encode($_POST['country'] ?? $defaultCountry) ?>;
    const postedPrefix  = <?= json_encode($_POST['phone_prefix'] ?? '') ?>;
    const defaultCountry = <?= json_encode($defaultCountry) ?>;

    function setPrefixFromOption() {
      const txt = sel.options[sel.selectedIndex]?.textContent || '';
      const m = txt.match(/\((\+\d+)\)$/);
      if (m) phonePrefix.value = m[1];
    }

    // Fallback minimal si CDN indispo
    const fallback = [
      {name:'Belgium', iso2:'BE', dial:'+32'},
      {name:'France', iso2:'FR', dial:'+33'},
      {name:'Netherlands', iso2:'NL', dial:'+31'},
      {name:'Germany', iso2:'DE', dial:'+49'},
      {name:'Luxembourg', iso2:'LU', dial:'+352'}
    ];

    fetch("https://cdn.jsdelivr.net/npm/intl-tel-input@23.6.1/src/js/data.js", {cache:'force-cache'})
      .then(r => r.text())
      .then(js => {
        const m = js.match(/(\[{\s*name:.*\n\];)/s);
        if (!m) throw new Error('data array not found');
        let data;
        eval("data=" + m[1]
          .replace(/name:/g,'"name":')
          .replace(/iso2:/g,'"iso2":')
          .replace(/dialCode:/g,'"dialCode":'));
        const list = data.map(d => ({
          name: d.name,
          iso2: (d.iso2||'').toUpperCase(),
          dial: '+' + String(d.dialCode).replace(/^\+/, '')
        })).filter(d => d.name && d.iso2 && d.dial);

        sel.innerHTML = list
          .map(d => `<option value="${d.iso2}" ${d.iso2===postedCountry?'selected':''}>${d.name} (${d.dial})</option>`)
          .join('');

        // Si aucun POST, impose le pays par défaut lié à la langue
        if (!<?= json_encode(isset($_POST['country'])) ?>) {
          const idx = Array.from(sel.options).findIndex(o => o.value === defaultCountry);
          if (idx >= 0) sel.selectedIndex = idx;
        }

        if (!postedPrefix) setPrefixFromOption();
        sel.addEventListener('change', setPrefixFromOption);
      })
      .catch(() => {
        sel.innerHTML = fallback
          .map(d => `<option value="${d.iso2}" ${d.iso2===postedCountry?'selected':''}>${d.name} (${d.dial})</option>`)
          .join('');
        if (!postedPrefix) {
          const def = fallback.find(d => d.iso2 === defaultCountry);
          phonePrefix.value = def ? def.dial : '+32';
        }
        sel.addEventListener('change', setPrefixFromOption);
      });
  })();
  </script>
</body>
</html>
