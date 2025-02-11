import os
from pathlib import Path
import ffmpeg
from PIL import Image
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

class MusicVideoGenerator:
    def __init__(self, audio_path, ass_path, output_path, images_dir=None):
        self.audio_path = audio_path
        self.ass_path = ass_path
        self.output_path = output_path
        self.images_dir = images_dir  # 可以为 None
        self.target_width = 1920
        self.target_height = 1080
        
    def process_image(self, image_path, output_path):
        """将图片处理成1920x1080，保持比例，多余部分用黑色填充"""
        with Image.open(image_path) as img:
            # 创建黑色背景
            background = Image.new('RGB', (self.target_width, self.target_height), 'black')
            
            # 计算缩放比例
            width_ratio = self.target_width / img.width
            height_ratio = self.target_height / img.height
            scale_ratio = min(width_ratio, height_ratio)
            
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
        
    def create_slideshow(self, duration_per_image=5):
        """创建图片轮播视频"""
        if not self.images_dir or not os.path.exists(self.images_dir):
            print("未找到背景图片，将使用纯白色背景")
            stream = ffmpeg.input(
                'color=c=white:s=1920x1080',
                f='lavfi',
                t=3600,
                r=24  # 设置帧率为24fps
            )
            return stream, self.target_width, self.target_height
        
        images = glob.glob(os.path.join(self.images_dir, "*.[jJ][pP][gG]"))
        
        if not images:
            print("未找到背景图片，将使用纯白色背景")
            stream = ffmpeg.input(
                'color=c=white:s=1920x1080',
                f='lavfi',
                t=3600,
                r=24  # 设置帧率为24fps
            )
            return stream, self.target_width, self.target_height
        
        # 创建临时目录存放处理后的图片
        temp_dir = tempfile.mkdtemp()
        processed_images = []
        
        try:
            print("正在处理背景图片...")
            for i, img_path in enumerate(images):
                output_path = os.path.join(temp_dir, f"processed_{i}.jpg")
                self.process_image(img_path, output_path)
                processed_images.append(output_path)
            
            # 创建图片轮播视频流
            stream = ffmpeg.input(
                f"concat:{','.join(processed_images)}", 
                pattern_type='glob',
                framerate=1/duration_per_image,
                r=24  # 设置帧率为24fps
            )
            
            return stream, self.target_width, self.target_height
            
        finally:
            # 清理临时文件
            shutil.rmtree(temp_dir)
    
    def calculate_max_font_size(self, ass_path, base_font_size=60, max_width=1850):
        """计算最大可用字体大小"""
        try:
            # 读取 ASS 文件找出最长的一行
            max_length = 0
            with open(ass_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('Dialogue:'):
                        # 提取文本内容
                        text = line.split(',')[-1].strip()
                        # 移除 ASS 标签
                        text = re.sub(r'{[^}]*}', '', text)
                        # 计算实际显示长度（中文字符算1.5个单位）
                        display_length = sum(1.5 if '\u4e00' <= c <= '\u9fff' else 1 for c in text)
                        max_length = max(max_length, display_length)
            
            if max_length == 0:
                return base_font_size
            
            # 估算字体大小
            # max_width = 字幕最大宽度（像素）
            # max_length = 最长行的显示单位
            # 假设每个单位宽度约等于字体大小
            estimated_font_size = int(max_width / (max_length * 1.1))  # 1.1 是安全系数，比之前小
            
            # 限制字体大小范围
            min_font_size = 35  # 增加最小字体大小
            max_font_size = base_font_size
            
            font_size = max(min(estimated_font_size, max_font_size), min_font_size)
            
            print(f"字幕信息:")
            print(f"最长行显示单位: {max_length}")
            print(f"计算得到字体大小: {font_size}")
            
            return font_size
            
        except Exception as e:
            print(f"计算字体大小时出错: {str(e)}")
            return base_font_size
    
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
        # 创建视频
        if self.images_dir and os.path.exists(self.images_dir):
            # 使用背景图片
            image_files = [f for f in os.listdir(self.images_dir) 
                          if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
            if image_files:
                background = os.path.join(self.images_dir, image_files[0])
        else:
            background = None
        
        # 创建图片轮播
        video_stream, width, height = self.create_slideshow()
        
        # 处理音频输入
        audio_stream = ffmpeg.input(self.audio_path)
        
        # 获取音频文件信息
        try:
            probe = ffmpeg.probe(self.audio_path)
            audio_info = next(s for s in probe['streams'] if s['codec_type'] == 'audio')
            
            # 获取音频参数
            sample_rate = audio_info.get('sample_rate', '44100')
            bit_rate = audio_info.get('bit_rate', '320k')
            channels = audio_info.get('channels', 2)
            
            print(f"源文件音频信息:")
            print(f"采样率: {sample_rate}Hz")
            print(f"比特率: {bit_rate}bps")
            print(f"声道数: {channels}")
            
        except Exception as e:
            print(f"无法读取音频信息，使用默认参数: {str(e)}")
            sample_rate = '44100'
            bit_rate = '320k'
            channels = 2
        
        # 将路径转换为适合 FFmpeg 的格式
        ass_path = self.ass_path.replace('\\', '/')
        
        # 计算适合的字体大小
        font_size = self.calculate_max_font_size(self.ass_path)
        
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
            start_time = datetime.now()

            # 获取音频总时长
            probe = ffmpeg.probe(self.audio_path)
            duration = float(probe['format']['duration'])
            print(f"视频长度: {duration/60:.1f}分钟")

            # 使用时间戳和随机数生成唯一的临时文件名
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            random_suffix = os.urandom(4).hex()
            temp_prefix = f"temp_{timestamp}_{random_suffix}"
            
            # 创建临时文件（使用规范化的路径）
            output_dir = os.path.dirname(os.path.abspath(self.output_path))
            temp_output = os.path.normpath(os.path.join(output_dir, f"{temp_prefix}_output.mp4"))

            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)

            try:
                # 使用GPU直接处理完整视频
                output = ffmpeg.output(
                    video_stream,
                    audio_stream,
                    temp_output,
                    **{
                        'acodec': 'aac',
                        'audio_bitrate': bit_rate,
                        'ar': sample_rate,
                        'ac': channels,
                        'vf': f"subtitles='{ass_path}':force_style='FontSize={font_size},ScaleX=1.5,ScaleY=1.5'",
                        'shortest': None,
                        'pix_fmt': 'yuv420p',
                        'r': 24,
                        'vcodec': 'h264_nvenc',
                        'preset': 'p7',
                        'rc': 'vbr',
                        'cq': 18,
                        'b:v': '5M',
                        'maxrate': '10M',
                        'bufsize': '10M',
                        'spatial_aq': 1,
                        'temporal_aq': 1,
                        'loglevel': 'error'  # 只显示错误信息
                    }
                )
                
                # 静默执行ffmpeg命令
                output.run(overwrite_output=True, capture_stdout=True, capture_stderr=True)
                
                # 移动临时文件到最终位置
                shutil.move(temp_output, self.output_path)
                print("✓ 视频处理完成")

                end_time = datetime.now()
                print(f"耗时: {(end_time - start_time).total_seconds():.1f}秒")

            except ffmpeg.Error as e:
                error_message = e.stderr.decode() if e.stderr else str(e)
                # 只显示最后一行错误信息
                error_message = error_message.strip().split('\n')[-1]
                print(f"视频处理失败: {error_message}")
                raise

        except Exception as e:
            print(f"\n视频处理失败: {str(e)}")
            raise
        finally:
            # 清理临时文件（静默执行）
            try:
                if os.path.exists(temp_output):
                    os.remove(temp_output)
            except:
                pass

def clean_filename(filename: str) -> str:
    """清理文件名，移除特殊字符和空格，便于比较"""
    # 移除扩展名
    filename = os.path.splitext(filename)[0]
    # 移除特殊字符，只保留字母、数字和中文字符
    return re.sub(r'[^\w\u4e00-\u9fff]', '', filename.lower())

def calculate_similarity(str1: str, str2: str) -> float:
    """计算两个字符串的相似度"""
    # 清理并标准化文件名
    str1_clean = clean_filename(str1)
    str2_clean = clean_filename(str2)
    # 计算相似度
    return SequenceMatcher(None, str1_clean, str2_clean).ratio()

def process_single_video(audio_path, ass_files, output_dir, similarity_threshold, processed_count, total_files):
    """处理单个视频的函数"""
    audio_name = Path(audio_path).stem
    print(f"\n{audio_name}")  # 简化输出，只显示文件名
    
    # 检查输出文件是否已存在
    output_path = os.path.join(output_dir, f"{audio_name}.mp4")
    if os.path.exists(output_path):
        print("→ 已存在，跳过")
        print(f"进度: {processed_count}/{total_files}")
        print("-" * 50)
        return "skipped"
    
    # 寻找最匹配的字幕文件
    best_match = None
    best_similarity = 0
    
    for ass_path in ass_files:
        ass_name = Path(ass_path).stem
        similarity = calculate_similarity(audio_name, ass_name)
        
        if similarity > best_similarity:
            best_similarity = similarity
            best_match = ass_path
    
    # 如果相似度达到阈值，开始生成视频
    if best_similarity >= similarity_threshold:
        try:
            print(f"→ 匹配字幕: {Path(best_match).name} ({best_similarity:.0%})")
            
            generator = MusicVideoGenerator(
                audio_path=audio_path,
                ass_path=best_match,
                output_path=output_path
            )
            
            generator.generate_video()
            
            # 删除使用过的 ass 文件
            try:
                os.remove(best_match)
            except Exception as e:
                print(f"! 字幕文件删除失败")
            
            return "success"
            
        except Exception as e:
            print(f"! 处理失败: {str(e)}")
            return "failed"
    else:
        if best_match:
            print(f"→ 未找到匹配字幕 (最接近: {Path(best_match).name}, {best_similarity:.0%})")
        else:
            print("→ 未找到匹配字幕")
        return "no_subtitle"

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