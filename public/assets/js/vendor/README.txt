Vendored third-party JavaScript
===============================

pdf.js (pdfjs-dist)
-------------------
Files   : pdf.min.js, pdf.worker.min.js
Version : 3.11.174
Source  : https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/
Upstream: https://github.com/mozilla/pdf.js
License : Apache License 2.0 (see the @licstart banner at the top of pdf.min.js)
sha256  : pdf.min.js        5B5799E6F8C680663207AC5B42EE14EED2A406FA7AF48F50C154F0C0B1566946
          pdf.worker.min.js FEABDF309770ED24BBA31A5467836CDC8CF639C705AF27D52B585B041BB8527B
Purpose : Client-side rendering of uploaded certificate PDFs so QR codes can be
          detected in the browser. No uploaded document leaves the device.

html5-qrcode is NOT vendored here; it is bundled once at
public/assets/js/html5-qrcode.min.js (mebjas/html5-qrcode, Apache-2.0) and is
reused for camera scanning, QR-image decoding and PDF-page decoding.

To update pdf.js: download the two files for the desired release from the
cdnjs/pdfjs-dist build output, replace them here, and update the version and
sha256 values above.
