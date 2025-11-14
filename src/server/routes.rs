use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestMethod {
    Post,
    Get,
    Put,
    Delete,
    Head,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MediaType {
    AAC,
    AVIF,
    Any,
    BMP,
    Binary,
    Bytes,
    CBR,
    CBZ,
    CSS,
    CSV,
    Calendar,
    EPUB,
    EXE,
    EventStream,
    FLAC,
    Form,
    FormData,
    GIF,
    GZIP,
    HTML,
    Icon,
    JPEG,
    JSON,
    JavaScript,
    JsonApi,
    MOV,
    MP3,
    MP4,
    MPEG,
    Markdown,
    MsgPack,
    OGG,
    OPF,
    OTF,
    PDF,
    PNG,
    Plain,
    RAR,
    SVG,
    TAR,
    TIFF,
    TTF,
    Text,
    WASM,
    WAV,
    WEBA,
    WEBM,
    WEBP,
    WOFF,
    WOFF2,
    XHTML,
    XML,
    ZIP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredRoute {
    uri: String,
    method: RequestMethod,
    media: Option<MediaType>,
}

pub struct RequiredRoutes {
    routes: Vec<RequiredRoute>,
}
