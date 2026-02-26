import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from flask import Flask, request, jsonify
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import asyncio


#EMOTES BY YASH X CODEX



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
auto_start_running = {}  # Dictionary to track running auto-start processes by team code
#------------------------------------------#

app = Flask(__name__)

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB52"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.120.2"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019116753"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
    elif TypE == 'OnLine': online_writer.write(PacKeT) ; await online_writer.drain()
    else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 

# ==================== AUTO START BOT (/lw) FUNCTION ====================
async def auto_start_loop(team_code):
    """Auto start bot that joins team, spams start, waits, leaves, and repeats"""
    global online_writer, whisper_writer, key, iv, region, auto_start_running
    
    try:
        count = 0
        print(f"🤖 Auto Start Bot started for team: {team_code}")
        
        while auto_start_running.get(team_code, False):
            count += 1
            print(f"🔄 Cycle #{count} for team {team_code}")
            
            # Step 1: Join the team
            join_packet = await GenJoinSquadsPacket(team_code, key, iv)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
            print(f"✅ Joined team: {team_code}")
            await asyncio.sleep(1)
            
            # Step 2: Spam start packets for 18 seconds (default)
            start_packet = await FS(key, iv)
            start_time = time.time()
            spam_count = 0
            
            while time.time() - start_time < 18:  # 18 seconds default
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', start_packet)
                spam_count += 1
                await asyncio.sleep(0.1)  # 100ms delay between start packets
            
            print(f"✅ Spammed {spam_count} start packets in 18 seconds")
            
            # Step 3: Wait in lobby for 20 seconds (default)
            print(f"⏳ Waiting 20 seconds in lobby...")
            await asyncio.sleep(20)
            
            # Step 4: Leave squad
            leave_packet = await ExiT(None, key, iv)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)
            print(f"✅ Left team: {team_code}")
            
            # Small delay before next cycle
            await asyncio.sleep(2)
        
        print(f"🛑 Auto Start Bot stopped for team: {team_code}")
        
    except Exception as e:
        print(f"❌ Error in auto_start_loop for team {team_code}: {e}")
        auto_start_running[team_code] = False

# ==================== STOP AUTO START FUNCTION ====================
async def stop_auto_start(team_code):
    """Stop auto start for a specific team"""
    global auto_start_running
    
    if team_code in auto_start_running:
        auto_start_running[team_code] = False
        return True
    return False

# ==================== SIMPLE /lw API ENDPOINT ====================
@app.route('/lw')
def auto_start_api():
    """
    SIMPLE API URL: http://127.0.0.1:10000/lw?team_code=ABC123
    """
    global loop, auto_start_running
    
    # Get parameters
    team_code = request.args.get('team_code')
    
    # Validate required parameters
    if not team_code:
        return jsonify({
            "status": "error", 
            "message": "Missing team_code parameter",
            "format": "http://127.0.0.1:10000/lw?team_code=ABC123"
        })
    
    # Check if bot is connected
    if online_writer is None:
        return jsonify({"status": "error", "message": "Bot not connected to server"})
    
    # Check if already running for this team
    if auto_start_running.get(team_code, False):
        return jsonify({
            "status": "error", 
            "message": f"Auto start already running for team: {team_code}",
            "stop_url": f"http://127.0.0.1:10000/stop_lw?team_code={team_code}"
        })
    
    # Start auto start process
    auto_start_running[team_code] = True
    asyncio.run_coroutine_threadsafe(
        auto_start_loop(team_code), 
        loop
    )
    
    # Return simple success response
    return jsonify({
        "status": "success",
        "message": f"Auto start bot started for team: {team_code}",
        "team_code": team_code,
        "duration": "18 seconds",
        "wait": "20 seconds",
        "stop_url": f"http://127.0.0.1:10000/stop_lw?team_code={team_code}"
    })

# ==================== SIMPLE STOP /lw API ENDPOINT ====================
@app.route('/stop_lw')
def stop_auto_start_api():
    """
    SIMPLE API URL: http://127.0.0.1:10000/stop_lw?team_code=ABC123
    """
    global loop
    
    # Get parameters
    team_code = request.args.get('team_code')
    
    if not team_code:
        return jsonify({
            "status": "error", 
            "message": "Missing team_code parameter",
            "format": "http://127.0.0.1:10000/stop_lw?team_code=ABC123"
        })
    
    # Stop auto start
    asyncio.run_coroutine_threadsafe(
        stop_auto_start(team_code), 
        loop
    )
    
    return jsonify({
        "status": "success",
        "message": f"Auto start bot stopped for team: {team_code}"
    })

# ==================== SIMPLE STATUS API ENDPOINT ====================
@app.route('/status')
def status_api():
    """Simple status check"""
    global auto_start_running
    
    running_teams = [team for team, running in auto_start_running.items() if running]
    
    return jsonify({
        "status": "success",
        "bot_connected": online_writer is not None,
        "running_teams": running_teams
    })

# ==================== QUICK EMOTE ATTACK FUNCTION (/q) ====================
async def quick_emote_attack(team_code, target_uids, emote_id, key, iv, region):
    """Join team, perform emote to multiple UIDs, and leave automatically"""
    try:
        # Step 1: Join the team
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', join_packet)
        print(f"🤖 Joined team: {team_code}")
        
        # Minimal delay for team to register
        await asyncio.sleep(0.2)
        
        # Step 2: Perform emote to all target UIDs
        for target_uid in target_uids:
            try:
                emote_packet = await Emote_k(int(target_uid), int(emote_id), key, iv, region)
                await SEndPacKeT(None, online_writer, 'OnLine', emote_packet)
                print(f"🎭 Performed emote {emote_id} to UID {target_uid}")
                await asyncio.sleep(0.05)  # Small delay between emotes
            except Exception as e:
                print(f"❌ Failed to send emote to {target_uid}: {e}")
        
        # Step 3: Leave the team immediately
        await asyncio.sleep(0.1)
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', leave_packet)
        print(f"🚪 Left team: {team_code}")
        
        return True, f"Quick emote attack completed! Sent emote to {len(target_uids)} player(s)"
        
    except Exception as e:
        return False, f"Quick emote attack failed: {str(e)}"

# ==================== /q API ENDPOINT ====================
@app.route('/q')
def quick_emote_api():
    """
    API URL Format: http://127.0.0.1:10000/q?tc={tc}&uid1={uid1}&uid2={uid2}&uid3={uid3}&uid4={uid4}&emote_id={emote_id}
    """
    global loop, online_writer, key, iv, region
    
    # Get parameters
    team_code = request.args.get('tc')
    uid1 = request.args.get('uid1')
    uid2 = request.args.get('uid2')
    uid3 = request.args.get('uid3')
    uid4 = request.args.get('uid4')
    emote_id = request.args.get('emote_id')
    
    # Validate required parameters
    if not team_code:
        return jsonify({
            "status": "error", 
            "message": "Missing parameter: tc (team code)",
            "format": "http://127.0.0.1:10000/q?tc={tc}&uid1={uid1}&uid2={uid2}&uid3={uid3}&uid4={uid4}&emote_id={emote_id}"
        })
    
    if not emote_id:
        return jsonify({
            "status": "error", 
            "message": "Missing parameter: emote_id",
            "format": "http://127.0.0.1:10000/q?tc={tc}&uid1={uid1}&uid2={uid2}&uid3={uid3}&uid4={uid4}&emote_id={emote_id}"
        })
    
    # Collect all provided UIDs
    target_uids = []
    if uid1 and uid1.isdigit():
        target_uids.append(uid1)
    if uid2 and uid2.isdigit():
        target_uids.append(uid2)
    if uid3 and uid3.isdigit():
        target_uids.append(uid3)
    if uid4 and uid4.isdigit():
        target_uids.append(uid4)
    
    # Check if at least one UID is provided
    if not target_uids:
        return jsonify({
            "status": "error", 
            "message": "At least one UID (uid1) is required",
            "format": "http://127.0.0.1:10000/q?tc={tc}&uid1={uid1}&uid2={uid2}&uid3={uid3}&uid4={uid4}&emote_id={emote_id}"
        })
    
    # Validate emote ID
    if not emote_id.isdigit():
        return jsonify({"status": "error", "message": "emote_id must be a number"})
    
    # Check if bot is connected
    if online_writer is None:
        return jsonify({"status": "error", "message": "Bot not connected to server"})
    
    # Start quick emote attack asynchronously
    asyncio.run_coroutine_threadsafe(
        quick_emote_attack(team_code, target_uids, emote_id, key, iv, region), 
        loop
    )
    
    # Return success response
    return jsonify({
        "status": "success",
        "message": "Quick emote attack initiated",
        "team_code": team_code,
        "targets": {
            "uid1": uid1,
            "uid2": uid2 if uid2 else None,
            "uid3": uid3 if uid3 else None,
            "uid4": uid4 if uid4 else None
        },
        "emote_id": emote_id,
        "total_targets": len(target_uids),
        "action": "Join → Emote → Leave"
    })

# ==================== SIMPLIFIED /qsimple API ====================
@app.route('/qsimple')
def quick_emote_simple_api():
    """Simplified version with single UID"""
    team_code = request.args.get('tc')
    target_uid = request.args.get('uid')
    emote_id = request.args.get('eid')
    
    if not team_code or not target_uid or not emote_id:
        return jsonify({"status": "error", "message": "Missing parameters"})
    
    asyncio.run_coroutine_threadsafe(
        quick_emote_attack(team_code, [target_uid], emote_id, key, iv, region), 
        loop
    )
    
    return jsonify({"status": "success", "team_code": team_code, "uid": target_uid, "emote_id": emote_id})

           
async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer , spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , XX , uid , Spy,data2, Chat_Leave
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        print(data2.hex()[10:])
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        print(packet)
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)


                        message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! '
                        P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)

                    except:
                        if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                            try:
                                print(data2.hex()[10:])
                                packet = await DeCode_PackEt(data2.hex()[10:])
                                print(packet)
                                packet = json.loads(packet)
                                OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                                JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)


                                message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! \n\n{get_random_color()}- Commands : @a {xMsGFixinG("123456789")} {xMsGFixinG("909000001")}\n\n[00FF00]Dev : @{xMsGFixinG("DEVXTLIVE")}'
                                P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                            except:
                                pass

            online_writer.close() ; await online_writer.wait_closed() ; online_writer = None

        except Exception as e: print(f"- ErroR With {ip}:{port} - {e}") ; online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave, auto_start_running
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: whisper_writer.write(pK) ; await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):

                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None


                    if response:
                        # ==================== SIMPLE /lw COMMAND IN CHAT ====================
                        if inPuTMsG.strip().startswith('/lw '):
                            print('Processing /lw command in chat')
                            
                            parts = inPuTMsG.strip().split()
                            
                            if len(parts) < 2:
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /lw (team_code)\nExample: /lw ABC123\n"
                                P = await SEndMsG(response.Data.chat_type, error_msg, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            else:
                                team_code = parts[1]
                                
                                # Check if already running
                                if auto_start_running.get(team_code, False):
                                    error_msg = f"[B][C][FF0000]❌ Auto start already running for team: {team_code}\nUse /stop_lw {team_code} to stop\n"
                                    P = await SEndMsG(response.Data.chat_type, error_msg, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                else:
                                    # Send initial message
                                    initial_msg = f"[B][C][00FF00]🤖 AUTO START BOT ACTIVATED!\n\nTeam: {team_code}\nDuration: 18 seconds\nWait: 20 seconds\nAction: Join → Spam Start → Wait → Leave → Repeat\n\nTo stop: /stop_lw {team_code}\n"
                                    P = await SEndMsG(response.Data.chat_type, initial_msg, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    
                                    # Start auto start
                                    auto_start_running[team_code] = True
                                    asyncio.create_task(auto_start_loop(team_code))
                        
                        # ==================== SIMPLE /stop_lw COMMAND IN CHAT ====================
                        if inPuTMsG.strip().startswith('/stop_lw'):
                            print('Processing /stop_lw command in chat')
                            
                            parts = inPuTMsG.strip().split()
                            
                            if len(parts) < 2:
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /stop_lw (team_code)\nExample: /stop_lw ABC123\n"
                                P = await SEndMsG(response.Data.chat_type, error_msg, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            else:
                                team_code = parts[1]
                                
                                if team_code in auto_start_running:
                                    auto_start_running[team_code] = False
                                    success_msg = f"[B][C][00FF00]✅ Auto start bot stopped for team: {team_code}\n"
                                    P = await SEndMsG(response.Data.chat_type, success_msg, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                else:
                                    error_msg = f"[B][C][FF0000]❌ No auto start running for team: {team_code}\n"
                                    P = await SEndMsG(response.Data.chat_type, error_msg, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                        
                        # ==================== QUICK EMOTE COMMAND (/q) IN CHAT ====================
                        if inPuTMsG.strip().startswith('/q '):
                            print('Processing quick emote command in chat')
                            
                            parts = inPuTMsG.strip().split()
                            
                            if len(parts) < 3:
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /q (team_code) (emote_id) [uid1] [uid2] [uid3] [uid4]\nExample: /q ABC123 909050009 123456789 987654321\n"
                                P = await SEndMsG(response.Data.chat_type, error_msg, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            else:
                                team_code = parts[1]
                                emote_id = parts[2]
                                
                                # Collect target UIDs (remaining parts)
                                target_uids = []
                                for i in range(3, min(len(parts), 7)):  # Max 4 UIDs (uid1-uid4)
                                    if parts[i].isdigit():
                                        target_uids.append(parts[i])
                                
                                # If no UIDs specified, use sender's UID
                                if not target_uids:
                                    target_uids = [str(response.Data.uid)]
                                
                                # Send initial message
                                initial_msg = f"[B][C][FFFF00]⚡ QUICK EMOTE ATTACK!\nTeam: {team_code}\nEmote: {emote_id}\nTargets: {len(target_uids)} player(s)\n"
                                P = await SEndMsG(response.Data.chat_type, initial_msg, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                # Execute quick emote attack
                                success, result = await quick_emote_attack(team_code, target_uids, emote_id, key, iv, region)
                                
                                if success:
                                    success_msg = f"[B][C][00FF00]✅ QUICK EMOTE SUCCESS!\n{result}\n"
                                else:
                                    success_msg = f"[B][C][FF0000]❌ QUICK EMOTE FAILED!\n{result}\n"
                                
                                P = await SEndMsG(response.Data.chat_type, success_msg, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                        
                        if inPuTMsG.startswith(("/5")):
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nAccepT My InV FasT\n\n"
                                P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                                PAc = await OpEnSq(key , iv,region)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , PAc)
                                C = await cHSq(5, uid ,key, iv,region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , C)
                                V = await SEnd_InV(5 , uid , key , iv,region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , V)
                                E = await ExiT(None , key , iv)
                                await asyncio.sleep(3)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , E)
                            except:
                                print('msg in squad')



                        if inPuTMsG.startswith('/x/'):
                            CodE = inPuTMsG.split('/x/')[1]
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                EM = await GenJoinSquadsPacket(CodE , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)


                            except:
                                print('msg in squad')

                        if inPuTMsG.startswith('leave'):
                            leave = await ExiT(uid,key,iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , leave)

                        if inPuTMsG.strip().startswith('/s'):
                            EM = await FS(key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)


                        if inPuTMsG.strip().startswith('/f'):

                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nOnLy In SQuaD ! \n\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                            except:
                                print('msg in squad')

                                parts = inPuTMsG.strip().split()
                                print(response.Data.chat_type, uid, chat_id)
                                message = f'[B][C]{get_random_color()}\nACITVE TarGeT -> {xMsGFixinG(uid)}\n'

                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)

                                uid2 = uid3 = uid4 = uid5 = uid6 = None
                                s = False

                                try:
                                    uid = int(parts[1])
                                    uid2 = int(parts[2])
                                    uid3 = int(parts[3])
                                    uid4 = int(parts[4])
                                    uid5 = int(parts[5])
                                    uid6 = int(parts[6])
                                    idT = int(parts[6])

                                except ValueError as ve:
                                    print("ValueError:", ve)
                                    s = True

                                except Exception:
                                    idT = len(parts) - 1
                                    idT = int(parts[idT])
                                    print(idT)
                                    print(uid)

                                if not s:
                                    try:
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                        # 🚀 Super Fast Emote Loop
                                        for i in range(200):  # repeat count
                                            print(f"Fast Emote {i+1}")
                                            H = await Emote_k(uid, idT, key, iv, region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)

                                            if uid2:
                                                H = await Emote_k(uid2, idT, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                            if uid3:
                                                H = await Emote_k(uid3, idT, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                            if uid4:
                                                H = await Emote_k(uid4, idT, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                            if uid5:
                                                H = await Emote_k(uid5, idT, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                            if uid6:
                                                H = await Emote_k(uid6, idT, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)

                                            await asyncio.sleep(0.08)  # ⚡ super-fast delay

                                    except Exception as e:
                                        print("Fast emote error:", e)

                        if inPuTMsG.strip().startswith('/d'):

                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nOnLy In SQuaD ! \n\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                            except:
                                print('msg in squad')

                                parts = inPuTMsG.strip().split()
                                print(response.Data.chat_type, uid, chat_id)
                                message = f'[B][C]{get_random_color()}\nACITVE TarGeT -> {xMsGFixinG(uid)}\n'

                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)

                                uid2 = uid3 = uid4 = uid5 = uid6 = None
                                s = False

                                try:
                                    uid = int(parts[1])
                                    uid2 = int(parts[2])
                                    uid3 = int(parts[3])
                                    uid4 = int(parts[4])
                                    uid5 = int(parts[5])
                                    uid6 = int(parts[6])
                                    idT = int(parts[6])

                                except ValueError as ve:
                                    print("ValueError:", ve)
                                    s = True

                                except Exception:
                                    idT = len(parts) - 1
                                    idT = int(parts[idT])
                                    print(idT)
                                    print(uid)

                                if not s:
                                    try:
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                        H = await Emote_k(uid, idT, key, iv,region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)

                                        if uid2:
                                            H = await Emote_k(uid2, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid3:
                                            H = await Emote_k(uid3, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid4:
                                            H = await Emote_k(uid4, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid5:
                                            H = await Emote_k(uid5, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                            if uid6:
                                                H = await Emote_k(uid6, idT, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        

                                    except Exception as e:
                                        pass


                        if inPuTMsG in ("dev"):
                            uid = response.Data.uid
                            chat_id = response.Data.Chat_ID
                            message = '/d <uid1> <uid2>... <emoteid> /f <uid1> <uid2>... <emoteid> for fast emote'
                            P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                        response = None
                            
            whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
                    
                    	
                    	
        except Exception as e: print(f"ErroR {ip}:{port} - {e}") ; whisper_writer = None
        await asyncio.sleep(reconnect_delay)
# ---------------------- FLASK ROUTES ----------------------

loop = None

# API endpoint to create 5-player group
@app.route('/create-group')
def create_group():
    global loop
    size = request.args.get('size')
    target_uid = request.args.get('uid')
    
    if not size or not target_uid:
        return jsonify({"status": "error", "message": "Missing parameters: size and uid are required"})
    
    if size != "5":
        return jsonify({"status": "error", "message": "Only size=5 is supported for now"})
    
    try:
        uid_int = int(target_uid)
    except:
        return jsonify({"status": "error", "message": "UID must be an integer"})
    
    # Start group creation process asynchronously
    asyncio.run_coroutine_threadsafe(
        create_5_player_group(uid_int), loop
    )
    
    return jsonify({
        "status": "success",
        "message": f"5-player group creation started for UID: {target_uid}",
        "group_size": 5,
        "target_uid": target_uid
    })

async def create_5_player_group(target_uid: int):
    """Create 5-player group with the target UID"""
    global key, iv, region, online_writer, whisper_writer
    
    if online_writer is None:
        print("Bot not connected")
        return
    
    try:
        # Step 1: Open squad
        PAc = await OpEnSq(key, iv, region)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
        await asyncio.sleep(0.5)
        
        # Step 2: Change to 5-player squad
        C = await cHSq(5, target_uid, key, iv, region)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
        await asyncio.sleep(0.5)
        
        # Step 3: Send invitation to target UID
        V = await SEnd_InV(5, target_uid, key, iv, region)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
        await asyncio.sleep(0.5)
        
        # Step 4: Leave squad after 3 seconds
        await asyncio.sleep(3)
        E = await ExiT(None, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
        
        print(f"✅ 5-player group created for UID: {target_uid}")
        
    except Exception as e:
        print(f"❌ Error creating 5-player group: {str(e)}")

async def perform_emote(team_code: str, uids: list, emote_id: int):
    global key, iv, region, online_writer, BOT_UID

    if online_writer is None:
        raise Exception("Bot not connected")

    try:
        # 1. JOIN SQUAD (super fast)
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', EM)
        await asyncio.sleep(0.12)  # minimal sync delay

        # 2. PERFORM EMOTE instantly
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            await SEndPacKeT(None, online_writer, 'OnLine', H)

        # 3. LEAVE SQUAD instantly (correct bot UID)
        LV = await ExiT(BOT_UID, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', LV)
        await asyncio.sleep(0.03)

        return {"status": "success", "message": "Emote done & bot left instantly"}

    except Exception as e:
        raise Exception(f"Failed to perform emote: {str(e)}")


@app.route('/join')
def join_team():
    global loop
    team_code = request.args.get('tc')
    uid1 = request.args.get('uid1')
    uid2 = request.args.get('uid2')
    uid3 = request.args.get('uid3')
    uid4 = request.args.get('uid4')
    uid5 = request.args.get('uid5')
    uid6 = request.args.get('uid6')
    emote_id_str = request.args.get('emote_id')

    if not team_code or not emote_id_str:
        return jsonify({"status": "error", "message": "Missing tc or emote_id"})

    try:
        emote_id = int(emote_id_str)
    except:
        return jsonify({"status": "error", "message": "emote_id must be integer"})

    uids = [uid for uid in [uid1, uid2, uid3, uid4, uid5, uid6] if uid]

    if not uids:
        return jsonify({"status": "error", "message": "Provide at least one UID"})

    asyncio.run_coroutine_threadsafe(
        perform_emote(team_code, uids, emote_id), loop
    )

    return jsonify({
        "status": "success",
        "team_code": team_code,
        "uids": uids,
        "emote_id": emote_id_str,
        "message": "Emote triggered"
    })


def run_flask():
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)


# ---------------------- MAIN BOT SYSTEM ----------------------

async def MaiiiinE():
    global loop, key, iv, region, BOT_UID

    # BOT LOGIN UID
    BOT_UID = int('1482210279')  # <-- FIXED BOT UID

    Uid, Pw = '4333648430', '9A4E6C7ABDB3FC0002835F678E9E01ABE5C3347A40BA402CA958FD6303FA077F'

    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id or not access_token:
        print("ErroR - InvaLid AccounT")
        return None

    PyL = await EncRypTMajoRLoGin(open_id, access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE:
        print("TarGeT AccounT => BannEd / NoT ReGisTeReD !")
        return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    loop = asyncio.get_running_loop()

    LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
    if not LoGinDaTa:
        print("ErroR - GeTinG PorTs From LoGin DaTa !")
        return None

    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    
    # FIXED: Properly handle IP:Port splitting with error checking
    try:
        OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
        if ":" in OnLinePorTs:
            OnLineiP, OnLineporT = OnLinePorTs.split(":")
        else:
            print(f"Warning: Online_IP_Port format unexpected: {OnLinePorTs}")
            OnLineiP, OnLineporT = "127.0.0.1", "8080"  # Default fallback
    except Exception as e:
        print(f"Error parsing Online_IP_Port: {e}")
        OnLineiP, OnLineporT = "127.0.0.1", "8080"
    
    try:
        ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
        if ":" in ChaTPorTs:
            ChaTiP, ChaTporT = ChaTPorTs.split(":")
        else:
            print(f"Warning: AccountIP_Port format unexpected: {ChaTPorTs}")
            ChaTiP, ChaTporT = "127.0.0.1", "8081"  # Default fallback
    except Exception as e:
        print(f"Error parsing AccountIP_Port: {e}")
        ChaTiP, ChaTporT = "127.0.0.1", "8081"

    acc_name = LoGinDaTaUncRypTinG.AccountName
    print(f"Account Name: {acc_name}")
    print(f"Token: {ToKen}")
    print(f"Online Server: {OnLineiP}:{OnLineporT}")
    print(f"Chat Server: {ChaTiP}:{ChaTporT}")

    equie_emote(ToKen, UrL)

    AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(
        TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv,
                LoGinDaTaUncRypTinG, ready_event, region)
    )

    await ready_event.wait()
    await asyncio.sleep(1)

    task2 = asyncio.create_task(
        TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen)
    )

    os.system('clear')
    print(render('SG', colors=['white', 'green'], align='center'))
    print(f"\n - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}")
    print(" - BoT sTaTus > GooD | OnLinE ! (: \n")
    print("✅ AUTO START BOT (/lw) ADDED")
    print("✅ SIMPLE API URL: http://127.0.0.1:10000/lw?team_code=ABC123")
    print("✅ STOP API URL: http://127.0.0.1:10000/stop_lw?team_code=ABC123")
    print("✅ STATUS API: http://127.0.0.1:10000/status")
    print("\n✅ QUICK EMOTE COMMAND (/q) ADDED")
    print("✅ API ENDPOINT: /q?tc={tc}&uid1={uid1}&uid2={uid2}&uid3={uid3}&uid4={uid4}&emote_id={emote_id}")
    print("✅ Example: http://127.0.0.1:10000/q?tc=ABC123&uid1=123456789&uid2=987654321&emote_id=909050009")

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    await asyncio.gather(task1, task2)


async def StarTinG():
    while True:
        try:
            await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError:
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e:
            print(f"ErroR TcP - {e} => ResTarTinG ...")


if __name__ == '__main__':
    asyncio.run(StarTinG())