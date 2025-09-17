# ITU CRN Monitor 🎓

An automated tool for monitoring and enrolling in ITU (Istanbul Technical University) courses through the OBS (Öğrenci Bilgi Sistemi) system. This tool helps students automatically attempt to register for courses when spots become available.

## ✨ Features

- **Automated Login**: Seamlessly logs into ITU OBS system
- **Real-time Monitoring**: Continuously checks for course availability
- **GUI Interface**: User-friendly graphical interface for easy operation
- **Customizable CRNs**: Add/remove specific course codes (CRNs) to monitor
- **Configurable Intervals**: Set your preferred checking frequency
- **Real-time Feedback**: Live console output showing registration attempts and results
- **Success Notifications**: Clear alerts when course registration is successful

## 🚀 Quick Start

### Option 1: Use the Executable (Recommended)
1. Download `ITU-CRN-Monitor.exe` from the `dist` folder
2. Double-click to run the application
3. Enter your ITU OBS credentials
4. Add the CRNs you want to monitor
5. Click "Start Monitoring"

### Option 2: Run from Source Code

#### Prerequisites
- Python 3.7 or higher
- Required Python packages (see Installation section)

#### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/crn-req.git
   cd crn-req
   ```

2. Install required packages:
   ```bash
   pip install requests
   ```

3. Run the GUI version:
   ```bash
   python crn_taker_gui.py
   ```

   Or run the command-line version:
   ```bash
   python crn_taker.py
   ```

## 📖 How to Use

### GUI Version (Recommended)

1. **Launch the Application**: Run `ITU-CRN-Monitor.exe` or `python crn_taker_gui.py`

2. **Enter Credentials**: 
   - Username: Your ITU student number
   - Password: Your OBS password

3. **Configure CRNs**:
   - **CRNs to Add**: Enter course codes separated by commas (e.g., `22661, 22662, 22634`)
   - **CRNs to Remove**: Enter CRNs you want to drop (optional)
   - **Check Interval**: Set how often to check (default: 3.5 seconds)

4. **Start Monitoring**:
   - Click "Login" to authenticate
   - Once logged in, click "Start Monitoring"
   - The tool will continuously attempt to register for your specified courses

5. **Monitor Results**: Watch the console output for real-time updates and success notifications

### Command Line Version

1. Edit `crn_taker.py` and update the credentials:
   ```python
   USERNAME = "your_student_number"
   PASSWORD = "your_password"
   ```

2. Modify the CRN list in the `make_crn_request` function:
   ```python
   payload = {
       "ECRN": ["22661", "22662", "22634", "22636"],  # CRNs to add
       "SCRN": []  # CRNs to remove
   }
   ```

3. Run the script:
   ```bash
   python crn_taker.py
   ```

## ⚙️ Configuration

### CRN Format
- Enter CRNs as comma-separated values: `22661, 22662, 22634`
- No spaces around commas (or they will be trimmed automatically)
- CRNs should be 5-digit course registration numbers

### Check Interval
- Minimum recommended: 3.5 seconds
- Lower intervals may trigger rate limiting
- Higher intervals reduce monitoring frequency

### Default CRNs
The tool comes pre-configured with example CRNs. **Remember to change these to your desired courses!**

## 🔧 Building from Source

To create your own executable:

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Build the executable:
   ```bash
   pyinstaller --onefile --windowed --name ITU-CRN-Monitor crn_taker_gui.py
   ```

3. The executable will be created in the `dist` folder

## ⚠️ Important Notes

- **Use Responsibly**: This tool automates course registration attempts. Use it ethically and in accordance with ITU policies
- **Rate Limiting**: The tool includes built-in delays to avoid overwhelming the server
- **Credentials**: Never share your OBS credentials. The tool stores them temporarily in memory only
- **Network**: Ensure you have a stable internet connection
- **Timing**: Course registration periods have specific time windows - make sure you're using this during the correct registration period

## 🐛 Troubleshooting

### Common Issues

**Login Failed**
- Verify your username and password are correct
- Check if OBS is accessible from your network
- Try logging in manually through the web browser first

**JWT Token Error**
- This usually indicates a login issue
- Try logging out and back in to OBS manually
- Restart the application

**No CRN Results**
- Verify the CRN numbers are correct and current
- Check if the course registration period is active
- Ensure the courses exist in the current semester

**Connection Errors**
- Check your internet connection
- Verify ITU OBS is not under maintenance
- Try again after a few minutes

## 📁 Project Structure

```
crn-req/
├── crn_taker.py          # Command-line version
├── crn_taker_gui.py      # GUI version
├── ITU-CRN-Monitor.spec  # PyInstaller configuration
├── dist/
│   └── ITU-CRN-Monitor.exe  # Compiled executable
├── build/                # Build artifacts
└── README.md            # This file
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

This project is for educational purposes. Please use responsibly and in accordance with ITU's terms of service.

## ⚡ Tips for Success

1. **Start Early**: Begin monitoring as soon as course registration opens
2. **Multiple Attempts**: The tool will keep trying until you stop it
3. **Monitor Console**: Watch for success messages and error notifications
4. **Backup Plan**: Have alternative courses ready in case your first choices fill up
5. **Network Stability**: Use a reliable internet connection for best results

---

**Good luck with your course registration! 🎓✨**
