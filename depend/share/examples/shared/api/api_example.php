<?php

function oauth_request($url, $param = array())
{
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $param);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HEADER, false);
  $text = curl_exec($ch);
//print "OAUTH RESP: \"" . $text . "\"<br>\n";
  return (@json_decode($text, true));
}

$CLIENT_ID="root@srue";
$CLIENT_SECRET="root";
$SELF_URI = urlencode("http://127.0.0.1/api_example.php");

/* user's login authorization code */
$AUTH_CODE="";
if (isset($_GET['code']))
  $AUTH_CODE = trim($_GET['code']);
if (isset($_POST['code']))
  $AUTH_CODE = trim($_POST['code']);

/* to access api calls */
$ACCESS_TOKEN="";
if (isset($_GET['access_token']))
  $ACCESS_CODE = trim($_GET['access_token']);
if (isset($_POST['access_token']))
  $ACCESS_CODE = trim($_POST['access_token']);


if (strlen($AUTH_CODE) == 0) {
  if (isset($_POST['api_login'])) {
    /* obtain auth code & access token */
    $param = array(
        "client_id" => urlencode($CLIENT_ID),
        "grant_type" => "password",
        "username" => $_POST['username'],
        "password" => $_POST['password']
        );
    $resp = oauth_request("http://127.0.0.1:32079/token", $param);
//https://oauth.example.com/token?grant_type=password&username=USERNAME&password=PASSWORD&client_id=CLIENT_ID
    $AUTH_CODE = $resp['code'];
  } else {
  /* pass user/pass direct 
  print "<form action=\"http://127.0.0.1:32079/token\" type=\"post\">\n" .
    "<input type=\"hidden\" name=\"api_login\" value=\"\">\n" .
    "<input type=\"hidden\" name=\"grant_type\" value=\"password\">\n" .
    "<input disabled name=\"client_id\" value=\"" . htmlentities($CLIENT_ID) . "\">App:</input><br>\n" .
    "Username: <input name=\"username\"></input><br>\n" . 
    "Password: <input name=\"password\"></input><br>\n" . 
    "<input type=submit></form>";
*/

    /* login to get access code */
    print "<p><a href=\"http://127.0.0.1:32079/auth?response_type=token&client_id=" . $CLIENT_ID . "&redirect_uri=" . $SELF_URI . "&scope=read\">Login Via OAUTH</a>";

    /* login via page form */
    print "<form action=\"/api_example.php\" method=\"post\">\n" .
      "<input type=\"hidden\" name=\"api_login\" value=\"1\">\n" .
      "Username: <input name=\"username\"></input><br>\n" . 
      "Password: <input name=\"password\"></input><br>\n" . 
      "<input type=submit></form>";

  }

  if (strlen($AUTH_CODE) == 0) {
    return; /* i cannot do that, dave */
  }
}

print "- Account session authorized (" . $AUTH_CODE . ").<br>\n";

if (strlen($ACCESS_TOKEN) == 0) {
  /* obtain access token */
  $param = array(
      "client_id" => urlencode($CLIENT_ID),
      "client_secret" => urlencode($CLIENT_SECRET),
      "grant_type" => "authorization_code",
      "code" => urlencode($AUTH_CODE),
      "redirect_uri" => $SELF_URI
  );
  $resp = oauth_request("http://127.0.0.1:32079/token", $param);
  // {"access_token":"ACCESS_TOKEN","token_type":"bearer","expires_in":2592000,"refresh_token":"REFRESH_TOKEN","scope":"read","uid":100101,"info":{"name":"Mark E. Mark","email":"mark@thefunkybunch.com"}}
//  print "(access_code): "; print_r($resp); print "<br>\n";
  $ACCESS_TOKEN = trim($resp['access_token']);
}

if (strlen($ACCESS_TOKEN) == 0) {
  print "- API Access not available.<br>\n";
  exit;
}

/* perform an api action. */
print "- API Access available (" . $ACCESS_TOKEN . ").<br>\n";

/* update account via oauth page */
print "<p><a href=\"http://127.0.0.1:32079/admin?response_type=user&client_id=" . $CLIENT_ID . "&redirect_uri=" . $SELF_URI . "&scope=write\">Manage Account Via OAUTH</a>";

$param = array(
    "client_id" => urlencode($CLIENT_ID),
    "grant_type" => "user",
    "access_token" => urlencode($ACCESS_TOKEN),
);
if (isset($_POST['api_update'])) {
  $param['fullname'] = $_POST['fullname'];
  $param['address'] = $_POST['address'];
  $param['zipcode'] = $_POST['zipcode'];
  $param['phone'] = $_POST['phone'];
}
$resp = oauth_request("http://127.0.0.1:32079/admin", $param);

/* update account via page form */
print "<form action=\"/api_example.php\" method=\"post\">\n" .
  "<input type=\"hidden\" name=\"api_update\" value=\"1\">\n" .
  "fullname: <input name=\"fullname\" value=\"" . htmlentities($resp['fullname']) . "\"></input><br>\n" . 
  "address: <input name=\"address\" value=\"" . htmlentities($resp['address']) . "\"></input><br>\n" . 
  "zipcode: <input name=\"zipcode\" value=\"" . htmlentities($resp['zipcode']) . "\"></input><br>\n" . 
  "phone: <input name=\"phone\" value=\"" . htmlentities($resp['phone']) . "\"></input><br>\n" . 
  "<input type=submit></form>";


if (isset($_POST['api'])) {
  if ($_POST['api'] == "geo") {
    $param = array(
        "client_id" => urlencode($CLIENT_ID),
        "access_token" => urlencode($ACCESS_TOKEN),
    );
    if (isset($_POST['geo_scan'])) {
      $param['method'] = "geo.scan";
      $param['param'] = json_encode(array((double)$_POST['geo_lat'], (double)$_POST['geo_lon']));
    } else if (isset($_POST['geo_place'])) {
      $param['method'] = "geo.place";
      $param['param'] = json_encode(array(trim($_POST['geo_name'])));
    } else {
      /* uh oh */
      exit;
    }
    $resp = oauth_request("http://127.0.0.1:32079/api", $param);

if (isset($resp['result'])) {
  $result = $resp['result'];
  $_POST['geo_lat'] = $result['latitude'];
  $_POST['geo_lon'] = $result['longitude'];
  $_POST['geo_name'] = $result['name'];
  $_POST['geo_summary'] = $result['summary'];
  $_POST['geo_type'] = $result['type'];
}

print "<pre>\n";
print "REQUEST:" . json_encode($param);
print "<br>RESPONSE:" . json_encode($resp);
print "</pre>\n";
  }
}

/* geo op */ 
print "<form action=\"/api_example.php\" method=\"post\">\n";
print "<input type=\"hidden\" name=\"api\" value=\"geo\">\n";
print "<input type=\"hidden\" name=\"code\" value=\"" . $AUTH_CODE . "\">\n";
print "<input type=\"hidden\" name=\"access_token\" value=\"" . $ACCESS_TOKEN . "\">\n";
print "<input type=\"hidden\" name=\"id\" value=\"1\">\n";
print "Place: <input name=\"geo_name\" value=\"" . htmlentities($_POST['geo_name']) . "\">\n";
print "<input type=\"submit\" name=\"geo_place\" value=\"Find Place\">\n";
print "<br>\n";
print "Latitude: <input name=\"geo_lat\" value=\"" . htmlentities($_POST['geo_lat']) . "\">\n";
print "Longitude: <input name=\"geo_lon\" value=\"" . htmlentities($_POST['geo_lon']) . "\">\n";
print "<input type=\"submit\" name=\"geo_scan\" value=\"Find Location\">\n";
print "<br>\n";
print "<input name=\"geo_summary\" value=\"" . htmlentities($_POST['geo_summary']);
print "<input name=\"geo_type\" value=\"" . htmlentities($_POST['geo_type']);
print "</form>";

?>

