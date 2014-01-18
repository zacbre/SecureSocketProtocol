using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Compressions
{
    public class LzwCompression
    {
        private EncoderParameter parameter;
        private ImageCodecInfo encoderInfo;
        private EncoderParameters encoderParams;

        public LzwCompression(int Quality)
        {
            this.parameter = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)Quality);
            this.encoderInfo = GetEncoderInfo("image/jpeg");
            this.encoderParams = new EncoderParameters(2);
            this.encoderParams.Param[0] = parameter;
            this.encoderParams.Param[1] = new EncoderParameter(System.Drawing.Imaging.Encoder.Compression, (long)2);
        }

        public byte[] Compress(Bitmap bmp, byte[] AdditionInfo = null)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                if (AdditionInfo != null)
                    stream.Write(AdditionInfo, 0, AdditionInfo.Length);
                bmp.Save(stream, encoderInfo, encoderParams);
                return stream.ToArray();
            }
        }

        public void Compress(Bitmap bmp, Stream stream)
        {
            bmp.Save(stream, encoderInfo, encoderParams);
        }

        private ImageCodecInfo GetEncoderInfo(string mimeType)
        {
            ImageCodecInfo[] imageEncoders = ImageCodecInfo.GetImageEncoders();
            int num2 = imageEncoders.Length - 1;
            for (int i = 0; i <= num2; i++)
            {
                if (imageEncoders[i].MimeType == mimeType)
                {
                    return imageEncoders[i];
                }
            }
            return null;
        }
    }
}