import openai
from pytube import YouTube
from youtube_transcript_api import YouTubeTranscriptApi

 

# Set the API key

openai.api_key = "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"

def extract_video_id(url):
    # Split the URL using '?' as the delimiter
    url_parts = url.split('?')

    # Get the part after '?' which contains the parameters
    params_part = url_parts[1]

    # Split the parameters using '&' as the delimiter
    params = params_part.split('&')

    # Find the parameter that starts with 'v=' which contains the video ID
    video_id_param = next(param for param in params if param.startswith('v='))

    # Extract the video ID by removing 'v=' from the parameter
    video_id = video_id_param.split('=')[1]

    return video_id



def get_video_info(youtube_url):
    try:
        # Create a YouTube object from the URL
        youtube = YouTube(youtube_url)

        # Get the video title
        video_title = youtube.title

        # Get the duration of the video in seconds
        duration_seconds = youtube.length

        # Convert duration_seconds to HH:MM:SS format
        minutes, seconds = divmod(duration_seconds, 60)
        hours, minutes = divmod(minutes, 60)
        duration_formatted = "{:02d}:{:02d}:{:02d}".format(hours, minutes, seconds)

        return video_title, duration_formatted

    except Exception as e:
        print(f"Error: {e}")
        return None, None

 

def timestamps(transcripts: str, system_prompt: str, model="gpt-3.5-turbo-16k"):
    print(f"Creating timestamps with {model=}")
    response = openai.ChatCompletion.create(
        model=model,
        temperature=0,
        messages=[
            {"role": "system", "content": 'You are a helpful and friendly assistant.'},
            {"role": "user", "content": system_prompt},
        ],
    )

    timestamp = response["choices"][0]["message"]["content"]
    return timestamp


def create_timestamps_youtube_video(youtube_url):
    try:
        # Transcribe each chunked audio file using whisper speech2text
        video_id = extract_video_id(youtube_url)
        transcripts = YouTubeTranscriptApi.get_transcript(video_id=video_id)

        # Get the video title and duration
        video_title, video_duration = get_video_info(youtube_url)

        print(video_title)
        print(video_duration)

        # Create the system prompt using video information and the first few lines of the transcript
        # system_prompt = f'{video_title}\n{transcripts[0]["text"]}\n{transcripts[1]["text"]}\n{transcripts[0]["start"]}\n{transcripts[1]["start"]}\nThe total length of the video is {video_duration}\n Include timestamps in in 00:00 format and range of time that describe what is going on in 2-8 words, it should cover whole video and list size should be max 10-15.\n Return the response in list of dictionary like "timestamp":"", "notes":"" without any additional spaces and starting message of whole video'
        # system_prompt = f'{video_title}\n{transcripts[0]["text"]}\n{transcripts[0]["start"]}\n{transcripts[1]["text"]}\n{transcripts[1]["start"]}\nThe total length of the video is {video_duration} \n Include timestamps in hh:mm:ss format and provide me the not null and short one line summary for every five minutes like if one is generated at 00:00:00 so next one should be after 00:05:00 and last timestamp should be less than total length of the video.Do not give me code,return the response in list of dictionary like "timestamp":"", "notes":"" without any starting messages and spaces , direct list of dictionaries. Notes should not be null or empty'
        # system_prompt = f"{video_title}\n Use this {transcripts[0]['text']}\n{transcripts[0]['start']}\n{transcripts[1]['text']}\n{transcripts[1]['start']} for the required response\n The total length of the video is {video_duration} in hh:mm:ss format \n Include timestamps in hh:mm:ss format and provide me the not null and short one line summary for every five minutes not in every five seconds like if one is generated at 00:00:00 so next one should be after 00:05:00 and so on and do not give any timestamps beyond {video_duration}.Do not give me code,return the response in list of dictionary like 'timestamp':'', 'notes':''  without any starting messages and spaces , direct list of dictionaries."
        system_prompt = f'{video_title}\n{transcripts[0]["text"]}\n{transcripts[0]["start"]}\n{transcripts[1]["text"]}\n{transcripts[1]["start"]}\nThe total length of the video is {video_duration}/60 minutes \n Include timestamps in hh:mm:ss format and provide me the not null and short one line summary for every five minutes like if one is generated at 00:00:00 so next one should be after 00:05:00 and last timestamp should be less than total length of the video. Do not give me code,return the response in list of dictionary like "timestamp":"", "notes":"" without any starting messages and spaces , direct list of dictionaries.Notes should not be null or empty.'
        # Concatenate all transcriptions into a single transcript
        full_transcript = " ".join(item['text'] for item in transcripts)

        # Generate timestamps for the entire video transcript
        final_timestamps = timestamps(full_transcript, system_prompt=system_prompt)
        
        return final_timestamps

    except Exception as e:
        print(f"Error: {e}")
        return None
    
    
# youtube_url = "https://www.youtube.com/watch?v=s2skans2dP4"

 

# fin_timestamps = create_timestamps_youtube_video(youtube_url)

 

# print(fin_timestamps)
