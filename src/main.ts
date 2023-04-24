import { createApp } from "vue";
import elementPlus from "element-plus";
import moment from "moment/moment";
import momentZhCn from "moment/dist/locale/zh-cn";
import zhCn from "element-plus/es/locale/lang/zh-cn";
import App from "./App.vue";

import "./styles/index.css";
moment.updateLocale("zh-cn", momentZhCn);

createApp(App)
  .use(elementPlus, {
    locale: zhCn
  })
  .mount("#app");
