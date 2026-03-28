import cv2
import numpy as np

class QRScanner:
    """Interface to scan QR codes using OpenCV."""

    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def scan_from_file(self, image_path):
        """Extracts QR URL from an image file."""
        img = cv2.imread(image_path)
        if img is None:
            return None, "Invalid image file"
        
        val, pts, st_code = self.detector.detectAndDecode(img)
        if val:
            return val, None
        return None, "No QR code found in image"

    def scan_from_camera(self):
        """Captures a frame from a camera and scans for QR code."""
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None, "Could not access camera"

        found_val = None
        error = "Timeout or user cancelled"

        # Try to scan for up to 10 seconds
        import time
        start_time = time.time()
        
        while time.time() - start_time < 10:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Draw a scanning indicator
            cv2.putText(frame, "Scanning for QR... (Press 'q' or Wait 10s)", (10, 30), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            
            val, pts, st_code = self.detector.detectAndDecode(frame)
            if val:
                found_val = val
                break
            
            cv2.imshow("QR Scanner (Close with 'q')", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        cap.release()
        cv2.destroyAllWindows()
        
        if found_val:
            return found_val, None
        return None, error
