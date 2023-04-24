declare module "moment/dist/locale/*" {
  import type { LocaleSpecification } from "moment";
  const locale: LocaleSpecification;
  export default locale;
}
