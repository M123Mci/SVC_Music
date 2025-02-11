# SVC_Music
Singing video creation
一键将QQ音乐下载下来的音乐生成带字幕的k歌视频
QQ音乐需要开启下载字幕

解密功能
mflac,mogg --> flac,ogg
https://github.com/yllhwa/decrypt-mflac-frida

KaLaOK/

├── input/ # 输入文件目录

│ ├── lyrics/ # 歌词文件 (.lrc, .srt)

│ └── music/ # 加密音乐文件 (.mflac, .mgg)

├── middle/ # 中间文件目录

│ ├── Music/ # 解密后的音乐文件 (.flac, .ogg, .mp3)

│ └── ass/ # 转换后的字幕文件 (.ass)

└── output/ # 输出目录，存放生成的视频文件


python main.py


  使用方法
1. 确保已安装QQ音乐客户端
2. 运行程序前需要安装以下依赖：
   - Python 3.8+
   - frida
   - ffmpeg
   - 其他依赖（见 requirements.txt）

3. 运行程序：python main.py


程序会自动执行以下步骤：
1. 从QQ音乐目录移动文件到对应目录
2. 解密加密的音乐文件
3. 将LRC歌词转换为ASS字幕
4. 生成KTV效果视频

 视频效果
- 1920x1080分辨率
- 左右交替显示歌词
- 支持歌手和歌名标题显示

 注意事项
- 需要先在QQ音乐中下载歌曲
- 确保系统已安装ffmpeg并添加到环境变量
- 生成的视频默认使用NVIDIA GPU加速（如果可用）

文件说明
- `main.py`: 主程序入口
- `move_qq_files.py`: 移动QQ音乐文件
- `hook_qq_music.py`: 解密QQ音乐文件
- `AssConversion.py`: 歌词转换为ASS字幕
- `music_video_generator.py`: 生成KTV视频
- `hook_qq_music.js`: Frida脚本用于解密






代码目前未完善仅可用阶段
