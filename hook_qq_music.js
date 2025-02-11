const TARGET_DLL = "QQMusicCommon.dll";

var EncAndDesMediaFileConstructorAddr = Module.findExportByName(
  TARGET_DLL,
  "??0EncAndDesMediaFile@@QAE@XZ"
);

var EncAndDesMediaFileDestructorAddr = Module.findExportByName(
  TARGET_DLL,
  "??1EncAndDesMediaFile@@QAE@XZ"
);

var EncAndDesMediaFileOpenAddr = Module.findExportByName(
  TARGET_DLL,
  "?Open@EncAndDesMediaFile@@QAE_NPB_W_N1@Z"
);

var EncAndDesMediaFileGetSizeAddr = Module.findExportByName(
  TARGET_DLL,
  "?GetSize@EncAndDesMediaFile@@QAEKXZ"
);

var EncAndDesMediaFileReadAddr = Module.findExportByName(
  TARGET_DLL,
  "?Read@EncAndDesMediaFile@@QAEKPAEK_J@Z"
);

var EncAndDesMediaFileConstructor = new NativeFunction(
  EncAndDesMediaFileConstructorAddr,
  "pointer",
  ["pointer"],
  "thiscall"
);

var EncAndDesMediaFileDestructor = new NativeFunction(
  EncAndDesMediaFileDestructorAddr,
  "void",
  ["pointer"],
  "thiscall"
);

var EncAndDesMediaFileOpen = new NativeFunction(
  EncAndDesMediaFileOpenAddr,
  "bool",
  ["pointer", "pointer", "bool", "bool"],
  "thiscall"
);

var EncAndDesMediaFileGetSize = new NativeFunction(
  EncAndDesMediaFileGetSizeAddr,
  "uint32",
  ["pointer"],
  "thiscall"
);

var EncAndDesMediaFileRead = new NativeFunction(
  EncAndDesMediaFileReadAddr,
  "uint",
  ["pointer", "pointer", "uint32", "uint64"],
  "thiscall"
);

rpc.exports = {
  decrypt: function (srcFileName, tmpFileName) {
    try {
      var EncAndDesMediaFileObject = Memory.alloc(0x28);
      EncAndDesMediaFileConstructor(EncAndDesMediaFileObject);

      var fileNameUtf16 = Memory.allocUtf16String(srcFileName);
      var openResult = EncAndDesMediaFileOpen(EncAndDesMediaFileObject, fileNameUtf16, 1, 0);
      if (!openResult) {
        throw new Error("Failed to open source file");
      }

      var fileSize = EncAndDesMediaFileGetSize(EncAndDesMediaFileObject);
      if (fileSize === 0) {
        throw new Error("File size is 0");
      }

      var buffer = Memory.alloc(fileSize);
      var readSize = EncAndDesMediaFileRead(EncAndDesMediaFileObject, buffer, fileSize, 0);
      if (readSize === 0) {
        throw new Error("Failed to read file");
      }

      var data = buffer.readByteArray(fileSize);
      EncAndDesMediaFileDestructor(EncAndDesMediaFileObject);
      
      // 确保目标目录存在
      var fs = new File(tmpFileName, "wb");
      if (!fs) {
        throw new Error("Failed to create output file");
      }
      
      try {
        fs.write(data);
        fs.flush();
        fs.close();
      } catch (e) {
        throw new Error("Failed to write output file: " + e.message);
      }
      
      return {
        success: true,
        fileSize: fileSize,
        readSize: readSize
      };
    } catch (e) {
      throw new Error("Decryption failed: " + e.message);
    }
  },
};
