<template>
  <main v-loading="loading">
    <el-row justify="end" align="middle">
      <el-col :span="18">
        <h2>Share Anywhere</h2>
      </el-col>
      <el-col :span="6">
        <el-switch :active-icon="Moon" :inactive-icon="Sunny" v-model="isDark"></el-switch>
      </el-col>
    </el-row>
    <el-tabs v-model="activeName">
      <el-tab-pane label="设备列表" name="devices">
        <el-row style="margin-bottom: 12px" align="middle" justify="start">
          <el-button type="primary" @click="updateMachines" :loading="loading">更新</el-button>
        </el-row>
        <el-row style="width: 100%">
          <el-col :span="24">
            <el-collapse v-model="activateMachineName">
              <template v-if="machines.length === 0">
                <el-empty description="没有扫描到设备"></el-empty>
              </template>
              <el-collapse-item v-for="(item, idx) in machines" :key="idx" :name="item.name">
                <template #title>
                  <el-icon
                    style="margin-right: 12px"
                    v-if="isOffline(item.latest_timestamp)"
                    color="red"
                    ><CircleCloseFilled
                  /></el-icon>
                  <el-icon color="green" style="margin-right: 12px" v-else
                    ><SuccessFilled
                  /></el-icon>
                  <span>{{ item.hostname }} ({{ item.ip_addr }})</span>
                </template>
                <el-descriptions>
                  <el-descriptions-item label="API">
                    <span>{{ item.endpoint }}</span>
                  </el-descriptions-item>
                </el-descriptions>
              </el-collapse-item>
            </el-collapse>
          </el-col>
        </el-row>
      </el-tab-pane>
      <el-tab-pane label="配置" name="settings">
        <el-scrollbar height="430px">
          <el-row style="margin-top: 12px">
            <el-form label-width="100px">
              <el-form-item label="本机名称">
                <el-input readonly :model-value="appOptions.name"></el-input>
              </el-form-item>
              <el-form-item label="抑制">
                <el-switch v-model="inhibition" @change="updateInhibition"></el-switch>
              </el-form-item>
              <el-form-item label="协商密钥" inline-message>
                <el-input show-password :minlength="8" v-model="appOptions.broadcast_cipher">
                </el-input>
              </el-form-item>

              <el-form-item label="绑定设备">
                <el-select v-model="appOptions.interface">
                  <el-option value="0.0.0.0" label="全部"></el-option>
                  <el-option
                    v-for="(item, idx) in networkDevices"
                    :key="idx"
                    :value="item.addresses[0]"
                    :label="item.name"
                  >
                    <span style="float: left; font-weight: bold">{{ item.name }}</span>
                    <span style="float: right">{{ item.addresses[0] }}</span>
                  </el-option>
                </el-select>
              </el-form-item>
              <el-form-item label="组播监听地址">
                <el-input readonly v-model="appOptions.multicast_address"></el-input>
              </el-form-item>
              <el-form-item label="API监听地址">
                <el-input
                  readonly
                  :model-value="appOptions.interface + ':' + appOptions.http_listen_port"
                ></el-input>
              </el-form-item>
              <el-form-item label="证书">
                <el-switch
                  style="margin-right: 12px"
                  readonly
                  :model-value="existCerts"
                ></el-switch>
                <el-button @click="generateCert" type="primary" :disabled="existCerts"
                  >生成证书</el-button
                >
              </el-form-item>
              <el-form-item label="日志文件">
                <el-input readonly :model-value="appOptions.log.log_file || 'Stderr'"></el-input>
              </el-form-item>
              <el-form-item label="日志级别">
                <el-select readonly :model-value="appOptions.log.log_level || 'info'">
                  <el-option value="trace" label="TRACE" />
                  <el-option value="debug" label="DEBUG" />
                  <el-option value="info" label="INFO" />
                  <el-option value="error" label="ERROR" />
                </el-select>
              </el-form-item>
            </el-form>
          </el-row>
          <el-row justify="center" align="middle">
            <el-button type="primary">更新并重启</el-button>
          </el-row>
        </el-scrollbar>
      </el-tab-pane>
      <el-tab-pane label="内容" name="content"> </el-tab-pane>
    </el-tabs>
  </main>
</template>

<script setup lang="ts">
import { invoke, process } from "@tauri-apps/api";
import { computed, onMounted, ref } from "vue";
import { useDark } from "@vueuse/core";
import { Moon, Sunny } from "@element-plus/icons-vue";
import { ElMessage } from "element-plus";
import { SuccessFilled, CircleCloseFilled } from "@element-plus/icons-vue";
import moment from "moment/moment";

const isDark = useDark();
const loading = ref(false);
const activeName = ref("devices");

interface AppOptions {
  name: string;
  multicast_address: string;
  http_listen_port: number;
  interface: string;
  broadcast_cipher: string;
  log: {
    log_level?: "trace" | "debug" | "info" | "error";
    log_file?: string;
  };
  tls: {
    ca?: string;
    server_cert?: string;
    server_key?: string;
    client_cert?: string;
    client_key?: string;
  };
}

interface Machine {
  name: string;
  ip_addr?: string;
  latest_timestamp?: moment.Moment;
  hostname: string;
  endpoint: string;
}

interface NetworkDevice {
  name: string;
  desc?: string;
  addresses: string[];
}

const machines = ref<Array<Machine>>([]);
const networkDevices = ref<Array<NetworkDevice>>([]);
const activateMachineName = ref("");
const appOptions = ref<AppOptions>({
  broadcast_cipher: "",
  http_listen_port: 0,
  interface: "",
  log: {},
  multicast_address: "",
  name: "",
  tls: {}
});
const existCerts = computed(() => {
  const tls = appOptions.value.tls;
  return !!tls.ca && !!tls.server_cert && !!tls.server_key && !!tls.client_cert && !!tls.client_key;
});

const generateCert = async () => {
  try {
    loading.value = true;
    await invoke("create_selfsigned_chains");
    ElMessage.success("generate successful");
    await process.relaunch();
  } catch (e) {
    ElMessage.error(`generate failed: ${e}`);
  } finally {
    loading.value = false;
  }
};

const isOffline = (item?: moment.Moment) => {
  if (!item) {
    return false;
  }
  return moment().subtract(10, "s").isAfter(item);
};

onMounted(async () => {
  try {
    loading.value = true;
    await updateMachines();
    appOptions.value = await invoke<AppOptions>("get_app_config");
    networkDevices.value = await invoke<Array<NetworkDevice>>("list_network_devices");
    networkDevices.value = networkDevices.value.filter((item) => item.addresses.length > 0);
  } finally {
    loading.value = false;
  }
});

const updateMachines = async () => {
  try {
    loading.value = true;
    machines.value = await invoke<Array<Machine>>("list_devices_command");
  } catch (e) {
    ElMessage.error(`failed to list devices: ${e}`);
  } finally {
    loading.value = false;
  }
};

const inhibition = ref(false);
const updateInhibition = async (v: boolean) => {
  try {
    loading.value = true;
    await invoke("update_inhibition", {
      inhibition: v
    });
  } finally {
    loading.value = false;
  }
};
</script>
