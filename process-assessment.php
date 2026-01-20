<?php
// ===============================
// TRAITEMENT DU FORMULAIRE
// ===============================
$success = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    function clean($data) {
        return htmlspecialchars(trim($data));
    }

    // Données organisation
    $company   = clean($_POST['company'] ?? '');
    $sector    = clean($_POST['sector'] ?? '');
    $country   = clean($_POST['country'] ?? '');
    $employees = clean($_POST['employees'] ?? '');

    // Contact
    $name  = clean($_POST['name'] ?? '');
    $role  = clean($_POST['role'] ?? '');
    $email = clean($_POST['email'] ?? '');
    $phone = clean($_POST['phone'] ?? '');

    // NIS2
    $nis2_status = clean($_POST['nis2_status'] ?? '');
    $previous    = clean($_POST['previous_assessment'] ?? '');

    // Maturité & scope
    $maturity = isset($_POST['maturity']) ? implode(", ", $_POST['maturity']) : "None";
    $scope    = isset($_POST['scope']) ? implode(", ", $_POST['scope']) : "Not specified";

    $timeline = clean($_POST['timeline'] ?? '');
    $message_user = clean($_POST['message'] ?? '');

    // ===============================
    // EMAIL
    // ===============================
    $to = "dieudonne.nsabimana@cidns.eu";
    $subject = "📩 New NIS2 Assessment Request – $company";

    $message = "
NEW NIS2 ASSESSMENT REQUEST – CIDNS
=================================

ORGANIZATION
------------
Company: $company
Sector: $sector
Country: $country
Employees: $employees

CONTACT
-------
Name: $name
Role: $role
Email: $email
Phone: $phone

NIS2 QUALIFICATION
-----------------
Status: $nis2_status
Previous assessment: $previous

CYBERSECURITY MATURITY
---------------------
$maturity

REQUESTED SCOPE
---------------
$scope

TIMELINE
--------
$timeline

ADDITIONAL NOTES
----------------
$message_user
";

    $headers  = "From: CIDNS Website <no-reply@cidns.eu>\r\n";
    $headers .= "Reply-To: $email\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    mail($to, $subject, $message, $headers);

    $success = true;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Request NIS2 Assessment | CIDNS</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
body {
  font-family: Poppins, Arial, sans-serif;
  background: linear-gradient(to bottom, #1B263B, #0D1B2A);
  color: #F1FAEE;
  margin: 0;
}

.container {
  max-width: 900px;
  margin: 60px auto;
  background: #121212;
  padding: 40px;
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0,0,0,.6);
}

h1 { color: #4DA3FF; }
.subtitle { opacity: .85; margin-bottom: 30px; }

fieldset { border: none; margin-bottom: 30px; }
legend { color: #4DA3FF; font-weight: 600; }

label { display: block; margin: 12px 0 5px; }

input, select, textarea {
  width: 100%;
  padding: 10px;
  border-radius: 6px;
  border: none;
  background: #1e1e1e;
  color: #fff;
}

.checkbox-group label { font-weight: normal; }

textarea { min-height: 100px; }

button {
  background: #4DA3FF;
  color: #fff;
  border: none;
  padding: 14px 30px;
  border-radius: 6px;
  font-size: 1em;
  cursor: pointer;
  box-shadow: 0 0 12px #4DA3FF;
}

button:hover { background: #2c82ff; }

.success {
  text-align: center;
  padding: 60px;
}

.success h1 { color: #4DA3FF; }
</style>
</head>

<body>

<div class="container">

<?php if ($success): ?>

<div class="success">
  <h1>Thank you</h1>
  <p>
    Your NIS2 assessment request has been successfully sent.<br>
    A CIDNS expert will contact you shortly.
  </p>
</div>

<?php else: ?>

<h1>Request a NIS2 Assessment</h1>
<p class="subtitle">
This request allows CIDNS to prepare a tailored NIS2 readiness and compliance assessment.
</p>

<form method="post">

<fieldset>
<legend>1. Organization Information</legend>
<label>Company name *</label>
<input type="text" name="company" required>

<label>Sector *</label>
<select name="sector" required>
<option value="">-- Select --</option>
<option>Energy</option><option>Transport</option><option>Healthcare</option>
<option>Digital Infrastructure</option><option>Finance</option>
<option>Public Sector</option><option>Other</option>
</select>

<label>Country *</label>
<input type="text" name="country" required>

<label>Employees *</label>
<select name="employees" required>
<option>&lt; 50</option><option>50 – 250</option>
<option>250 – 1000</option><option>&gt; 1000</option>
</select>
</fieldset>

<fieldset>
<legend>2. Contact</legend>
<label>Full name *</label>
<input type="text" name="name" required>

<label>Role *</label>
<select name="role" required>
<option>CEO / Managing Director</option>
<option>CIO / CTO</option>
<option>CISO / Security Officer</option>
<option>IT Manager</option>
<option>Compliance / Legal</option>
</select>

<label>Email *</label>
<input type="email" name="email" required>

<label>Phone</label>
<input type="text" name="phone">
</fieldset>

<fieldset>
<legend>3. NIS2 Qualification</legend>
<label>Status</label>
<select name="nis2_status">
<option>Essential entity</option>
<option>Important entity</option>
<option>Not sure</option>
<option>Not applicable</option>
</select>

<label>Previous assessment</label>
<select name="previous_assessment">
<option>No</option>
<option>Internal</option>
<option>External audit</option>
<option>ISO 27001</option>
</select>
</fieldset>

<fieldset>
<legend>4. Cyber Maturity</legend>
<div class="checkbox-group">
<label><input type="checkbox" name="maturity[]" value="Policies"> Policies</label>
<label><input type="checkbox" name="maturity[]" value="Risk"> Risk management</label>
<label><input type="checkbox" name="maturity[]" value="IAM"> IAM / MFA</label>
<label><input type="checkbox" name="maturity[]" value="Incident"> Incident response</label>
<label><input type="checkbox" name="maturity[]" value="Backup"> Backup / DR</label>
<label><input type="checkbox" name="maturity[]" value="SOC"> SOC</label>
</div>
</fieldset>

<fieldset>
<legend>5. Scope</legend>
<div class="checkbox-group">
<label><input type="checkbox" name="scope[]" value="Readiness"> Readiness</label>
<label><input type="checkbox" name="scope[]" value="Risk"> Risk</label>
<label><input type="checkbox" name="scope[]" value="Governance"> Governance</label>
<label><input type="checkbox" name="scope[]" value="Technical"> Technical</label>
<label><input type="checkbox" name="scope[]" value="Incident"> Incident</label>
<label><input type="checkbox" name="scope[]" value="Full"> Full NIS2</label>
</div>

<label>Timeline</label>
<select name="timeline">
<option>&lt; 1 month</option>
<option>1 – 3 months</option>
<option>&gt; 3 months</option>
</select>
</fieldset>

<fieldset>
<legend>6. Additional info</legend>
<textarea name="message"></textarea>
<label><input type="checkbox" required> GDPR consent</label>
</fieldset>

<button type="submit">Submit Assessment Request</button>

</form>

<?php endif; ?>

</div>
</body>
</html>
