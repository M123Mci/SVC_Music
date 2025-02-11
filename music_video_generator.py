import os
from pathlib import Path
import ffmpeg
from PIL import Image, ImageFont, ImageDraw
import glob
import tempfile
import shutil
from difflib import SequenceMatcher
import re
import concurrent.futures
import psutil
import GPUtil
from datetime import datetime
import subprocess
import random
import math

class MusicVideoGenerator:
    def __init__(self, audio_path, ass_path, output_path, images_dir=None):
        self.audio_path = audio_path
        self.ass_path = ass_path
        self.output_path = output_path
        self.images_dir = images_dir if images_dir else "input/images"
        self.target_width = 1920
        self.target_height = 1080
        
        # 获取项目根目录（假设当前文件在项目根目录下）
        project_root = os.path.dirname(os.path.abspath(__file__))
        
        # 创建缓存目录（使用绝对路径）
        cache_path = os.path.join(project_root, "middle", "cache")
        
        # 直接使用 os.makedirs 创建目录
        try:
            if not os.path.exists(cache_path):
                os.makedirs(cache_path)
            self.cache_dir = Path(cache_path)
            self.auto_clean = False  # 添加自动清理标志
            print(f"使用缓存目录: {self.cache_dir}")
            
            # 验证目录是否可写
            test_file = self.cache_dir / "test.txt"
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception as e:
                print(f"缓存目录无写入权限: {str(e)}")
                raise
                
        except Exception as e:
            print(f"创建缓存目录失败: {str(e)}")
            raise
        
        # 添加缓存前缀（使用音频文件名）
        self.cache_prefix = clean_filename(os.path.splitext(os.path.basename(audio_path))[0])
        print(f"缓存前缀: {self.cache_prefix}")
        
    def process_image(self, image_path, output_path, is_pil_image=False):
        """将图片处理成1920x1080，尽可能占满屏幕，保持比例"""
        try:
            if is_pil_image:
                img = image_path  # 直接使用传入的PIL Image对象
            else:
                img = Image.open(image_path)
            
            # 创建黑色背景
            background = Image.new('RGB', (self.target_width, self.target_height), 'black')
            
            # 计算缩放比例
            width_ratio = self.target_width / img.width
            height_ratio = self.target_height / img.height
            
            # 使用较大的缩放比例，让图片尽可能大
            scale_ratio = max(width_ratio, height_ratio)
            
            # 计算缩放后的尺寸
            new_width = int(img.width * scale_ratio)
            new_height = int(img.height * scale_ratio)
            
            # 缩放图片
            resized_img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # 计算居中位置
            x = (self.target_width - new_width) // 2
            y = (self.target_height - new_height) // 2
            
            # 将缩放后的图片粘贴到黑色背景上
            background.paste(resized_img, (x, y))
            
            # 保存处理后的图片
            background.save(output_path, 'JPEG', quality=95)
            
            if not is_pil_image:
                img.close()
                
        except Exception as e:
            print(f"处理图片失败 {image_path}: {str(e)}")
            raise
        
    def create_slideshow(self, duration_per_image=5):
        """创建图片轮播视频"""
        try:
            # 使用类的缓存目录
            self.temp_dir = self.cache_dir
            print(f"使用缓存目录: {self.temp_dir}")
            
            # 先清理旧的缓存文件
            self.clean_cache()
            
            if not self.images_dir or not os.path.exists(self.images_dir):
                print("未找到背景图片，将使用纯白色背景")
                stream = ffmpeg.input(
                    'color=c=white:s=1920x1080',
                    f='lavfi',
                    t=3600,
                    r=24
                )
                return stream, self.target_width, self.target_height
            
            # 支持多种图片格式
            supported_formats = [
                "*.[jJ][pP][gG]",
                "*.[jJ][pP][eE][gG]",
                "*.[pP][nN][gG]",
                "*.[gG][iI][fF]",
                "*.[bB][mM][pP]",
                "*.[wW][eE][bB][pP]"
            ]
            
            # 收集所有支持格式的图片
            images = []
            for format_pattern in supported_formats:
                images.extend(glob.glob(os.path.join(self.images_dir, format_pattern)))
            
            if not images:
                print("未找到背景图片，将使用纯白色背景")
                stream = ffmpeg.input(
                    'color=c=white:s=1920x1080',
                    f='lavfi',
                    t=3600,
                    r=24
                )
                return stream, self.target_width, self.target_height
            
            # 随机打乱图片顺序
            random.shuffle(images)
            
            try:
                print("正在处理背景图片...")
                self.processed_files = []
                
                for i, img_path in enumerate(images):
                    # 获取图片文件名（不含扩展名）作为标识
                    img_name = clean_filename(os.path.splitext(os.path.basename(img_path))[0])
                    is_gif = img_path.lower().endswith('.gif')
                    
                    # 使用图片名称命名缓存文件
                    if is_gif:
                        output_path = self.temp_dir / f"{img_name}_gif.mp4"
                    else:
                        # 处理静态图片
                        img_output = self.temp_dir / f"{img_name}.jpg"
                        output_path = self.temp_dir / f"{img_name}.mp4"
                    
                    print(f"处理图片 {i+1}/{len(images)}: {os.path.basename(img_path)}")
                    
                    # 检查是否已存在处理过的文件
                    if output_path.exists():
                        print(f"使用已存在的缓存: {output_path.name}")
                        self.processed_files.append(output_path)
                        continue
                    
                    if is_gif:
                        # 处理 GIF，先获取 GIF 的原始时长
                        probe = ffmpeg.probe(img_path)
                        gif_duration = float(probe['streams'][0]['duration'])
                        
                        # 计算需要循环的次数以达到目标时长
                        loop_count = math.ceil(duration_per_image / gif_duration)
                        
                        # 处理 GIF
                        (
                            ffmpeg.input(img_path, stream_loop=loop_count-1)
                            .filter('scale', 
                                f'if(gte(iw/ih,{self.target_width}/{self.target_height}),'
                                f'{self.target_width},-1)',  # 改为直接使用目标宽度
                                f'if(gte(iw/ih,{self.target_width}/{self.target_height}),'
                                f'-1,{self.target_height})'  # 改为直接使用目标高度
                            )
                            .filter('pad',
                                self.target_width,
                                self.target_height,
                                '(ow-iw)/2',
                                '(oh-ih)/2',
                                'black'
                            )
                            .filter('fps', fps=24)
                            .output(
                                str(output_path),
                                t=duration_per_image,  # 精确控制输出时长
                                vcodec='libx264',
                                preset='ultrafast',
                                pix_fmt='yuv420p'
                            )
                            .overwrite_output()
                            .run(capture_stdout=True, capture_stderr=True)
                        )
                    else:
                        # 处理静态图片
                        self.process_image(img_path, str(img_output))
                        (
                            ffmpeg.input(str(img_output), loop=1)
                            .filter('fps', fps=24)
                            .output(
                                str(output_path),
                                t=duration_per_image,  # 精确控制输出时长
                                vcodec='libx264',
                                preset='ultrafast',
                                pix_fmt='yuv420p'
                            )
                            .overwrite_output()
                            .run(capture_stdout=True, capture_stderr=True)
                        )
                    
                    # 验证输出文件的时长
                    try:
                        probe = ffmpeg.probe(str(output_path))
                        actual_duration = float(probe['streams'][0]['duration'])
                        if abs(actual_duration - duration_per_image) > 0.1:  # 允许0.1秒的误差
                            print(f"警告: 片段时长不准确 ({actual_duration:.1f}s)")
                    except Exception as e:
                        print(f"警告: 无法验证片段时长: {str(e)}")
                    
                    self.processed_files.append(output_path)
                
                # 获取音频时长
                try:
                    probe = ffmpeg.probe(self.audio_path)
                    self.audio_duration = float(probe['format']['duration'])
                except Exception as e:
                    print(f"无法获取音频时长，使用默认值: {str(e)}")
                    self.audio_duration = 600  # 默认10分钟
                
                # 使用前缀命名连接文件
                self.concat_file = self.temp_dir / f"{self.cache_prefix}_concat.txt"
                with open(self.concat_file, 'w', encoding='utf-8') as f:
                    # 计算需要重复的次数，确保覆盖整个音频时长
                    total_duration = len(self.processed_files) * duration_per_image
                    self.repeat_count = math.ceil(self.audio_duration / total_duration)
                    
                    # 重复写入文件列表
                    for _ in range(self.repeat_count):
                        for file in self.processed_files:
                            rel_path = os.path.relpath(file, self.temp_dir)
                            safe_path = rel_path.replace('\\', '/')
                            f.write(f"file '{safe_path}'\n")
                            f.write(f"duration {duration_per_image}\n")
                
                # 创建最终的视频流
                stream = (
                    ffmpeg
                    .input(str(self.concat_file), f='concat', safe=0)
                    .filter('fps', fps=24)
                    .filter('format', 'yuv420p')
                )
                
                print(f"共处理 {len(self.processed_files)} 个图片/动画")
                print(f"单轮时长: {total_duration:.1f}秒")
                print(f"重复次数: {self.repeat_count}")
                print(f"总视频时长: {total_duration * self.repeat_count:.1f}秒")
                return stream, self.target_width, self.target_height
                
            except Exception as e:
                self.clean_cache()  # 出错时清理
                raise
        except Exception as e:
            self.clean_cache()  # 出错时清理
            raise
    
    def calculate_max_font_size(self, ass_path: str) -> int:
        """计算最佳字体大小"""
        try:
            # 读取字幕文件获取所有歌词行
            with open(ass_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 提取所有歌词文本
            lyrics = []
            for line in content.split('\n'):
                if line.startswith('Dialogue:'):
                    # 提取歌词文本（去除ASS标签）
                    text = re.sub(r'{[^}]*}', '', line.split(',')[-1])
                    lyrics.append(text)
            
            if not lyrics:
                return 60  # 降低默认大小
            
            # 创建一个临时图像来测试文本大小
            img = Image.new('RGB', (1920, 1080))
            draw = ImageDraw.Draw(img)
            
            # 二分查找合适的字体大小
            min_size = 80  # 进一步增大最小字号
            max_size = 300  # 大幅增加最大字体大小
            target_width = 1850  # 接近屏幕宽度
            
            while min_size < max_size:
                mid_size = (min_size + max_size + 1) // 2
                font = ImageFont.truetype("msyh.ttc", mid_size)
                
                # 检查所有歌词行
                is_size_ok = True
                for text in lyrics:
                    bbox = draw.textbbox((0, 0), text, font=font)
                    width = bbox[2] - bbox[0]
                    height = bbox[3] - bbox[1]
                    
                    # 最大限度放宽限制
                    if width > target_width or height > 300:  # 大幅增加高度限制
                        is_size_ok = False
                        break
                
                if is_size_ok:
                    min_size = mid_size
                else:
                    max_size = mid_size - 1
            
            # 完全不缩小
            font_size = min_size  # 直接使用计算出的大小，不缩小
            
            # 打印调试信息
            print(f"\n字体大小计算:")
            print(f"最长歌词: {max(lyrics, key=len)}")
            print(f"计算得到字体大小: {font_size}")
            
            # 验证最终尺寸
            font = ImageFont.truetype("msyh.ttc", font_size)
            max_width = max(draw.textbbox((0, 0), text, font=font)[2] for text in lyrics)
            print(f"最大文本宽度: {max_width}px (目标: {target_width}px)")
            
            return font_size
            
        except Exception as e:
            print(f"计算字体大小时出错: {str(e)}")
            return 60  # 降低默认大小
    
    def monitor_resources(self, stop_event):
        """监控系统资源使用情况"""
        try:
            while not stop_event.is_set():
                # CPU 使用率
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # 内存使用
                memory = psutil.virtual_memory()
                
                # GPU 信息
                try:
                    gpus = GPUtil.getGPUs()
                    gpu_info = []
                    for gpu in gpus:
                        gpu_info.append(f"GPU {gpu.id}: "
                                      f"显存使用: {gpu.memoryUsed}/{gpu.memoryTotal}MB "
                                      f"({gpu.memoryUtil*100:.1f}%), "
                                      f"负载: {gpu.load*100:.1f}%")
                except:
                    gpu_info = ["无法获取GPU信息"]
                
                # 打印资源使用情况
                print(f"\r资源监控 - CPU: {cpu_percent}% | "
                      f"内存: {memory.percent}% | "
                      f"{' | '.join(gpu_info)}", end='')
                
        except Exception as e:
            print(f"\n资源监控错误: {str(e)}")

    def process_video(self, video_stream, audio_stream, output_path, hw_accel='none', **params):
        """处理视频的具体实现"""
        try:
            output = ffmpeg.output(video_stream, audio_stream, output_path, **params)
            output.run(overwrite_output=True)
            return True
        except Exception as e:
            print(f"\n编码失败 ({hw_accel}): {str(e)}")
            return False

    def generate_video(self):
        try:
            # 创建视频流
            video_stream, width, height = self.create_slideshow()
            
            # 处理音频输入
            audio_stream = ffmpeg.input(self.audio_path)
            
            # 获取音频文件信息（静默处理）
            try:
                probe = ffmpeg.probe(self.audio_path)
                audio_info = next(s for s in probe['streams'] if s['codec_type'] == 'audio')
                sample_rate = audio_info.get('sample_rate', '44100')
                bit_rate = audio_info.get('bit_rate', '320k')
                channels = audio_info.get('channels', 2)
            except Exception:
                sample_rate = '44100'
                bit_rate = '320k'
                channels = 2
            
            # 计算字体大小
            font_size = self.calculate_max_font_size(self.ass_path)
            
            # 将路径转换为适合 FFmpeg 的格式
            ass_path = self.ass_path.replace('\\', '/')
            
            # 调整字幕位置和缩放
            style_params = [
                f"FontSize={font_size}",
                "MarginV=120",        # 增加垂直边距
                "MarginL=160",        # 增加左边距
                "MarginR=160",        # 增加右边距
                "Alignment=8",        # 改为顶部对齐
                "ScaleX=1",          # 不缩放
                "ScaleY=1",          # 不缩放
                "BorderStyle=1",      # 边框样式
                "Bold=1",            # 加粗
                "Outline=3",         # 增加描边宽度
                "Shadow=1",          # 添加阴影
                "ShadowDepth=2",     # 阴影深度
                "PlayResX=1920",     # 指定分辨率
                "PlayResY=1080"      # 指定分辨率
            ]
            
            # 检测显卡支持（静默执行）
            try:
                with open(os.devnull, 'w') as devnull:
                    probe_result = subprocess.check_output('ffmpeg -hide_banner -hwaccels', stderr=devnull, shell=True).decode()
                    encoders_result = subprocess.check_output('ffmpeg -hide_banner -encoders | findstr nvenc', stderr=devnull, shell=True).decode()
                
                hw_accel = 'cuda' if 'cuda' in probe_result.lower() and 'h264_nvenc' in encoders_result.lower() else 'none'
            except:
                hw_accel = 'none'

            try:
                print("\n开始处理视频...")
                
                # 获取音频时长
                probe = ffmpeg.probe(self.audio_path)
                duration = float(probe['format']['duration'])
                print(f"视频时长: {duration/60:.1f}分钟")

                try:
                    # 第一步：处理视频序列
                    temp_video = self.cache_dir / f"{self.cache_prefix}_temp_video.mp4"
                    temp_output = self.cache_dir / f"{self.cache_prefix}_output.mp4"
                    video_output = (
                        ffmpeg
                        .input(str(self.concat_file), f='concat', safe=0)
                        .filter('fps', fps=24)
                        .filter('format', 'yuv420p')
                        .output(
                            str(temp_video),
                            t=duration,
                            vcodec='h264_nvenc',
                            preset='p7',           # 最高质量预设
                            rc='vbr',             # 可变比特率
                            cq=20,                # 较低的 CQ 值保持画质
                            b='800k',             # 目标比特率
                            maxrate='1.5M',       # 最大比特率
                            bufsize='1.5M',       # 缓冲大小
                            spatial_aq=1,         # 空间自适应量化
                            temporal_aq=1,        # 时间自适应量化
                            profile='high',       # 高规格编码
                            level='4.1'           # 兼容级别
                        )
                    )
                    
                    print("→ 生成基础视频...")
                    video_output.run(overwrite_output=True, capture_stdout=True, capture_stderr=True)
                    
                    # 输出基础视频大小
                    base_size_mb = os.path.getsize(temp_video) / (1024 * 1024)
                    print(f"  基础视频大小: {base_size_mb:.1f}MB")
                    
                    # 第二步：添加字幕和音频
                    video_input = ffmpeg.input(str(temp_video))
                    audio_input = ffmpeg.input(self.audio_path)
                    
                    final_output = (
                        ffmpeg
                        .output(
                            video_input,
                            audio_input,
                            str(temp_output),
                            acodec='aac',
                            audio_bitrate=bit_rate,
                            ar=sample_rate,
                            ac=channels,
                            vf=f"subtitles='{ass_path}'"
                               f":force_style='{','.join(style_params)}'"
                               ":original_size=1920x1080",
                            shortest=None,
                            vcodec='h264_nvenc',
                            preset='p7',
                            rc='vbr',
                            cq=20,
                            b='800k',
                            maxrate='1.5M',
                            bufsize='1.5M',
                            spatial_aq=1,
                            temporal_aq=1,
                            profile='high',
                            level='4.1'
                        )
                    )
                    
                    print("→ 添加字幕和音频...")
                    final_output.run(overwrite_output=True, capture_stdout=True, capture_stderr=True)
                    
                    # 删除临时视频文件
                    if temp_video.exists():
                        temp_video.unlink()
                    
                    # 输出最终视频大小
                    final_size_mb = os.path.getsize(temp_output) / (1024 * 1024)
                    print(f"  最终视频大小: {final_size_mb:.1f}MB")
                    
                    # 移动到最终位置
                    shutil.move(temp_output, self.output_path)
                    print("✓ 处理完成")

                except ffmpeg.Error as e:
                    error_message = e.stderr.decode() if e.stderr else str(e)
                    print(f"! 处理失败: {error_message}")
                    raise

            except Exception as e:
                print(f"! 处理失败: {str(e)}")
                raise

        except Exception as e:
            print(f"! 处理失败: {str(e)}")
            raise

    def __del__(self):
        """析构函数：根据设置决定是否清理缓存"""
        if self.auto_clean:  # 只在需要时清理
            self.clean_cache()

    def clean_cache(self):
        """清理所有中间文件，包括临时视频、图片和连接文件"""
        if self.cache_dir and self.cache_dir.exists():
            try:
                # 需要删除的文件类型
                temp_patterns = [
                    # 临时视频文件
                    f"{self.cache_prefix}_temp_video.mp4",
                    f"{self.cache_prefix}_output.mp4",
                    # 连接文件
                    f"{self.cache_prefix}_concat.txt",
                    # 处理后的图片和视频片段
                    "*.jpg",  # 处理后的静态图片
                    "*.mp4"   # 处理后的视频片段（包括GIF转换的）
                ]
                
                # 删除所有临时文件
                for pattern in temp_patterns:
                    try:
                        # 使用 glob 处理通配符
                        if '*' in pattern:
                            for file_path in self.cache_dir.glob(pattern):
                                if file_path.exists():
                                    file_path.unlink()
                        else:
                            file_path = self.cache_dir / pattern
                            if file_path.exists():
                                file_path.unlink()
                    except Exception as e:
                        print(f"清理文件失败 {pattern}: {str(e)}")
                        
            except Exception as e:
                print(f"清理缓存目录失败: {str(e)}")

def clean_filename(filename: str) -> str:
    """清理文件名，只保留ffmpeg支持的字符"""
    # 保留文件扩展名
    name, ext = os.path.splitext(filename)
    
    # 替换规则
    # 1. 移除所有撇号和引号
    name = name.replace("'", "").replace('"', "")
    # 2. 保留字母、数字、中文字符、连字符和空格
    name = re.sub(r'[^\w\u4e00-\u9fff\- ]', '', name)
    # 3. 将多个空格替换为单个空格
    name = re.sub(r'\s+', ' ', name)
    # 4. 去除首尾空格
    name = name.strip()
    
    return name + ext

def calculate_similarity(str1: str, str2: str) -> float:
    """计算两个字符串的相似度"""
    # 清理并标准化文件名
    str1_clean = clean_filename(str1)
    str2_clean = clean_filename(str2)
    # 计算相似度
    return SequenceMatcher(None, str1_clean, str2_clean).ratio()

def process_single_video(audio_path, ass_files, output_dir, similarity_threshold, processed_count, total_files):
    """处理单个视频"""
    audio_name = Path(audio_path).stem
    print(f"\n{audio_name}")
    
    # 清理文件名
    clean_name = clean_filename(audio_name)
    if clean_name != audio_name:
        print(f"→ 清理文件名: {audio_name} -> {clean_name}")
        try:
            # 重命名音频文件
            new_audio_path = Path(audio_path).parent / f"{clean_name}{Path(audio_path).suffix}"
            os.rename(audio_path, new_audio_path)
            audio_path = str(new_audio_path)
            audio_name = clean_name
        except Exception as e:
            print(f"! 重命名音频文件失败: {str(e)}")
            return "failed"
    
    # 检查是否已存在
    output_path = os.path.join(output_dir, f"{audio_name}.mp4")
    if os.path.exists(output_path):
        print("→ 已存在，跳过")
        print(f"进度: {processed_count}/{total_files}")
        print("-" * 50)
        return "skipped"
    
    # 寻找匹配的字幕文件
    best_match = None
    best_similarity = 0
    
    # 创建字幕文件副本以避免修改原始文件
    ass_files_copy = []
    for ass_path in ass_files:
        ass_name = Path(ass_path).stem
        clean_ass_name = clean_filename(ass_name)
        if clean_ass_name != ass_name:
            try:
                # 在临时目录创建副本
                temp_dir = Path("temp")
                temp_dir.mkdir(exist_ok=True)
                new_ass_path = temp_dir / f"{clean_ass_name}{Path(ass_path).suffix}"
                shutil.copy2(ass_path, new_ass_path)
                ass_files_copy.append(str(new_ass_path))
            except Exception as e:
                print(f"! 创建字幕文件副本失败: {str(e)}")
                continue
        else:
            ass_files_copy.append(ass_path)
    
    # 使用清理后的字幕文件进行匹配
    for ass_path in ass_files_copy:
        similarity = calculate_similarity(audio_name, Path(ass_path).stem)
        if similarity > best_similarity:
            best_similarity = similarity
            best_match = ass_path
    
    # 生成视频
    try:
        if best_similarity >= similarity_threshold:
            print(f"→ 匹配字幕: {Path(best_match).name} ({best_similarity:.0%})")
            
            generator = MusicVideoGenerator(
                audio_path=audio_path,
                ass_path=best_match,
                output_path=output_path
            )
            
            generator.generate_video()
            print("✓ 视频生成完成")
            
            # 删除对应的 ASS 文件
            try:
                # 获取原始 ASS 文件路径（而不是临时副本的路径）
                original_ass_path = next(
                    ass for ass in ass_files 
                    if Path(ass).stem == Path(best_match).stem
                )
                os.remove(original_ass_path)
                print(f"→ 已删除字幕文件: {Path(original_ass_path).name}")
            except Exception as e:
                print(f"! 删除字幕文件失败: {str(e)}")
            
            return "success"
        else:
            if best_match:
                print(f"→ 无匹配字幕 ({Path(best_match).name}, {best_similarity:.0%})")
            else:
                print("→ 无匹配字幕")
            print(f"进度: {processed_count}/{total_files}")
            print("-" * 50)
            return "no_subtitle"
            
    except Exception as e:
        print(f"! 处理失败: {str(e)}")
        return "failed"
    finally:
        # 清理临时文件
        try:
            if 'temp_dir' in locals():
                shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass

def main():
    # 设置输入输出目录
    music_dir = 'middle/Music'
    ass_dir = 'middle/ass'
    output_dir = 'output'
    similarity_threshold = 0.8
    max_workers = 1  # 同时处理的视频数量
    
    # 获取所有音频文件
    audio_files = set()
    for ext in ['*.mp3', '*.flac', '*.ogg']:
        audio_files.update(glob.glob(os.path.join(music_dir, ext), recursive=True))
        audio_files.update(glob.glob(os.path.join(music_dir, ext.upper()), recursive=True))
    
    if not audio_files:
        print("未找到音频文件")
        return
    
    audio_files = sorted(list(audio_files), key=lambda x: Path(x).stem.lower())
    
    # 获取所有ASS文件
    ass_files = []
    for ext in ['*.ass', '*.ASS']:
        ass_files.extend(glob.glob(os.path.join(ass_dir, ext), recursive=True))
    
    if not ass_files:
        # 获取已有的MP4文件
        existing_videos = set()
        for ext in ['*.mp4', '*.MP4']:
            existing_videos.update(glob.glob(os.path.join(output_dir, ext)))
        existing_videos = {Path(v).stem for v in existing_videos}
        
        # 过滤掉已有视频的音频文件
        missing_subtitles = []
        for audio_path in audio_files:
            audio_name = Path(audio_path).stem
            if audio_name not in existing_videos:
                missing_subtitles.append(audio_name)
        
        print("\n处理结果:")
        if missing_subtitles:
            print(f"\n找不到字幕({len(missing_subtitles)}):")
            for name in missing_subtitles:
                print(name)
        else:
            print("\n所有音频文件都已有对应视频")
        return
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    # 统计计数器
    total_files = len(audio_files)
    results = {"success": 0, "failed": 0, "skipped": 0, "no_subtitle": 0}
    
    print(f"开始处理，共 {total_files} 个文件，将同时处理 {max_workers} 个视频")
    
    # 记录总处理开始时间
    total_start_time = datetime.now()
    processed_count = 0
    
    # 用于收集不同类型的文件
    skipped_files = []
    no_subtitle_files = []
    success_files = []
    failed_files = []
    
    # 使用线程池并行处理视频
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_audio = {
            executor.submit(
                process_single_video, 
                audio_path, 
                ass_files.copy(),
                output_dir, 
                similarity_threshold,
                i + 1,  # 处理计数
                total_files  # 总文件数
            ): audio_path for i, audio_path in enumerate(audio_files)
        }
        
        # 处理完成的任务
        for future in concurrent.futures.as_completed(future_to_audio):
            audio_path = future_to_audio[future]
            try:
                result = future.result()
                results[result] += 1
                
                # 收集文件名
                audio_name = Path(audio_path).stem
                if result == "skipped":
                    skipped_files.append(audio_name)
                elif result == "no_subtitle":
                    no_subtitle_files.append(audio_name)
                elif result == "failed":
                    failed_files.append(audio_name)
                    current_time = datetime.now()
                    elapsed_time = (current_time - total_start_time).total_seconds()
                    print(f"用时: {elapsed_time:.1f}秒")
                elif result == "success":
                    success_files.append(audio_name)
                    current_time = datetime.now()
                    elapsed_time = (current_time - total_start_time).total_seconds()
                    print(f"用时: {elapsed_time:.1f}秒")
                
            except Exception as e:
                failed_files.append(Path(audio_path).stem)
                print(f"! 发生错误: {str(e)}")
                results["failed"] += 1
    
    # 计算总耗时
    total_time = (datetime.now() - total_start_time).total_seconds()
    
    # 打印分类结果
    print("\n处理结果:")
    
    if skipped_files:
        print(f"\n视频已存在({len(skipped_files)}):")
        for file in skipped_files:
            print(file)
    
    if no_subtitle_files:
        print(f"\n找不到字幕({len(no_subtitle_files)}):")
        for file in no_subtitle_files:
            print(file)
    
    if success_files:
        print(f"\n处理成功({len(success_files)}):")
        for file in success_files:
            print(file)
    
    if failed_files:
        print(f"\n处理失败({len(failed_files)}):")
        for file in failed_files:
            print(file)
    
    print(f"\n总耗时: {total_time:.1f}秒")
    
    if success_files:
        print(f"平均每个视频耗时: {total_time/len(success_files):.1f}秒")

if __name__ == "__main__":
    main() 