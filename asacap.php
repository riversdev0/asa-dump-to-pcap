<?php
/* 
 * This script is designed to receive the output of the "show capture xyz dump" command on a Cisco
 *   ASA and turn it into a PCAP file. This script is written in PHP, which means that it must run
 *   on a webserver, not as a command line script (i.e. like Perl does). The benefit of this is that
 *   it can be hosted publicly on a internet webserver (by you) without having to authenticate to a
 *   shell.
 *
 * This script works by receiving an html form submission that contains a bunch of text output that
 *   you paste in from the ASA firewall. It digests that text and creates a file on the webserver
 *   with the PCAP output.
 * 
 * Notes:
 * - this script generates the name of the outputed PCAP file by using the date and time. Therefore,
 *   it will experience issues if more than one person submits a form in the same second.
 * - you can modify the variables below to affect the behavior of the script.
 * 
 */

// set debug to something greater than 0 to see debug output. This helps troubleshoot bugs in the
//   script. Normally, this should stay 0.
$debug = 0;

// the path on the hard drive for the file to be stored. Use a trailing slash. This path needs to
//   be served by the webserver so that you can download the file when it's created.
$local_path = "/var/www/html/asa-dump-to-pcap/";

// the relative HTTP path on the web server where the above upload path (the "local_path") is found.
//   Use a trailing slash.
$http_path = "/asa-dump-to-pcap/";

// the maximum number of characters that the textarea will accept.
$max_chars = 500000;

// save the input hex data to a text file in case any troubleshooting is needed
$save_input = 1;

//
// START OF SCRIPT -- DON'T MODIFY STUFF PAST THIS POINT
//

if ($_SERVER['REQUEST_METHOD']=="POST") {
  echo "<html><body>\n";
  if (isset($_POST['capbytes'])) {
    // assess the form input and see if we're going to do anything
    if ($debug>0) { echo $_POST['capbytes']; }
    if (strlen($_POST['capbytes']) > $max_chars) {
      die ("The textarea only accepts ".number_format($max_chars)." characters. Please submit a smaller section of capture, or modify the script to accomodate more.");
    }

    // save the input text for reference
    if ($save_input > 0) {
      $fname = date("Md-His").".txt";
      $handle = fopen($local_path.$fname,"x") or die("Could not open the output folder to write the file.");
      fwrite($handle,$_POST['capbytes']);
      fclose($handle);
      unset($handle);
    }

    // start the interpretation
    $capture_lines = explode("\r\n",$_POST['capbytes']);

    if ($debug>0) {
      /* append blank line so the line numbers match up */ array_unshift($capture_lines,"");
      print_r($capture_lines);
      /* shift the blank line off the beginning of the array */ array_shift($capture_lines);
      echo "There are ".count($capture_lines)." lines in the input.\n";
    }

    // give the file a name and open it
    $fname = date("Md-His").".pcap";
    $handle = fopen($local_path.$fname,"x") or die("Could not open the output folder to write the file.");

    // write the header to the file
    $data = pack("N",0xa1b2c3d4);
    $data .= pack("n",0x0002);
    $data .= pack("n",0x0004);
    $data .= pack("N",0x00000000);
    $data .= pack("N",0x00000000);
    $data .= pack("N",0x00040000);
    $data .= pack("N",0x00000001);
    fwrite($handle,$data);
    unset($data);

    // start parsing the input for packets
    $line_counter = 0; $byte_counter = 0;
    foreach($capture_lines as $this_line) {
      $line_counter++;
      // if ($debug>0) { echo "line number: {$line_counter}<br />\nbyte_counter: {$byte_counter}<br />\n"; }
      // if we have a blank line, then ingore the line
      if (strlen($this_line) == 0) {
      }
      // if we have the '<--more-->' characters, then ignore the line
      elseif (substr($this_line,0,14)=="<--- More --->") {
      }
      // if we have 14 space characters, then ignore the line
      elseif (substr($this_line,0,14)=="              ") {
      }
      // if we have a hash within 20 or so characters, then ignore the line
      elseif (preg_match("/#/",substr($this_line,0,20))) {
      }
      // if we find the phrase 'packets captured', then ignore the line
      elseif (substr($this_line,-16) == "packets captured") {
      }
      // if we find the phrase 'packets shown', then write out the data
      elseif (substr($this_line,-13) == "packets shown") {
        if(isset($header)&&isset($data)) {
          // write out the previous packet data
          $header .= pack("N",$byte_counter);
          $header .= pack("N",$byte_counter);
          fwrite($handle,$header.$data);
          unset($header,$data,$byte_counter);
        }
      }
      // if we have a colon at the 5th characters, then we have a new header, and we should write out whatever we've collected
      elseif (substr($this_line,4,1) == ":") {
        if ($debug>0) { echo "Found new header at line {$line_counter}<br />\n"; }
        if(isset($header)&&isset($data)) {
          if ($debug>0) { echo "byte_counter is: {$byte_counter}<br />\n"; }
          // write out the previous packet data
          $header .= pack("N",$byte_counter) . pack("N",$byte_counter);
          fwrite($handle,$header.$data);
          unset($header,$data,$byte_counter);
        } else {
          if ($debug>0) { echo "Previous header does not exist<br />\n"; }
        }
        // start a new packet
        $header = ""; $data = ""; $byte_counter = 0;
        $seconds = strtotime(substr($this_line,6,8));
        $microseconds = intval(substr($this_line,15,6));
        if ($debug>0) { echo "seconds: {$seconds}, microseconds: {$microseconds}<br />\n"; }
        $header .= pack("N",$seconds);
        if ($debug>0) { echo "microseconds printf: "; printf("%'06s",$microseconds); echo "\n";}
        $microseconds = sprintf("%'06s",$microseconds);
        $header .= pack("N",$microseconds);
      }
      // if we have a 0x as the first two characters, then we have packet data
      elseif (substr($this_line,0,2) == "0x") {
        if ($debug>0) { echo "here's what we start with: \"{$this_line}\"<br />\n"; } 
        // whack the first 6 characters and then trim the string
        $this_line = trim(substr($this_line,6));
        // grab the first 39 characters and then remove whitespace
        $this_line = preg_replace('/\s+/', '', substr($this_line,0,39));
        if ($debug>0) { echo "here's what we have left: \"{$this_line}\"<br />\n"; } 
        // break the line into words
        $bytes = str_split($this_line,4);
        if ($debug>0) { echo var_dump($bytes); }
        foreach ($bytes as $short) {
          if (strlen($short) == 2) {
            $byte_counter++;
            $data .= pack("H*",$short);
          } elseif (strlen($short) == 4) {
            $byte_counter+=2;
            $data .= pack("H*",$short);
          } elseif (strlen($short) > 4) {
            $byte_counter+=2;
            $data .= pack("H*",substr($short,0,4));
          }
        }
        if ($debug>0) { echo "byte_conter is: {$byte_counter}<br />\n"; }
      }
      // any other condition
      else {
        echo "Encountered a line which we don't understand: {$this_line}<br />\nContinuing...<br />\n";
      }
    }
    // write out any data that might be left in the variables
    if(isset($header)&&isset($data)) {
      // write out the previous packet data
      $header .= pack("N",$byte_counter) . pack("N",$byte_counter);
      fwrite($handle,$header.$data);
      unset($header,$data,$byte_counter);
    }
    echo "Parsed {$line_counter} lines.<br />\n";
    fclose($handle);
    echo "The PCAP file was created: <a href=\"".$http_path.$fname."\">{$fname}</a><br />\n";
    echo "Submit <a href=\"?\">another dump</a>.<br />\n";
  } else {
    echo "Nothing was submitted.\n";
  }
  echo "</body></html>";
} else {
  echo "<html><body style=\"font-family:Verdana,Geneva,Tahoma,Arial;font-size:.9em;\">\n".
    "<form method=\"post\">\n".
    "<div style=\"width:700;margin-bottom:15px;\">This script converts the output of the \"<em>show capture xyz dump</em>\" command ".
    "from an ASA and converts it into a pcap file. The box below accepts ".number_format($max_chars)." characters. Paste in the output and then click ".
    "\"Submit\".<br /><br />\nWritten by riversdev0 on Aug 11, 2015.<br />This project is available on Github here: <a href=\"https://github.com/riversdev0/asa-dump-to-pcap\" target=\"_blank\">https://github.com/riversdev0/asa-dump-to-pcap</a></div>\n".
    "<div style=\"margin-bottom:15px;\"><textarea name=\"capbytes\" cols=\"95\" rows=\"26\" maxlength=\"{$max_chars}\"></textarea></div>".
    "<input type=\"submit\" />\n".
    "</form>\n".
    "</body></html>";
}
?>
