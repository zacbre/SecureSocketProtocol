namespace SecureSocketProtocol2.Controls
{
    partial class uTorrentProgressBar
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.SuspendLayout();
            // 
            // ProgressBarEx
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Name = "ProgressBarEx";
            this.Size = new System.Drawing.Size(180, 26);
            this.SizeChanged += new System.EventHandler(this.ProgressBarEx_SizeChanged);
            this.Paint += new System.Windows.Forms.PaintEventHandler(this.ProgressBarEx_Paint);
            this.ResumeLayout(false);

        }

        #endregion
    }
}
