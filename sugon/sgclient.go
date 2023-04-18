package sugon

import (
	"bytes"
	"encoding/json"
	"fmt"
	logger "github.com/urchinfs/sugon-sdk/dflog"
	"github.com/urchinfs/sugon-sdk/util"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
)

type Sgclient interface {

	// get file list for path.
	GetFileList(path, keyWord string, start, limit int64) (*FileList, error)

	// get file list recursively
	GetFileListRecursive(path, keyWord string, start, limit int64, maxDepth int) ([]FileMeta, error)

	// check file or directory exist.
	FileExist(path string) (bool, error)

	// create dir for given path, auto create parent dir if not exist.
	CreateDir(path string) (bool, error)

	// delete dir or file for given path, recursively children dirs if exist.
	DeleteFile(path string) (bool, error)

	// get file list meta for given path
	GetFilesMeta(path, keyWord string, start, limit int64) ([]FileMeta, error)

	// get file meta for given file
	GetFileMeta(path string) (*FileMeta, error)

	// download file or directory
	Download(path string) (io.ReadCloser, error)

	// upload
	Upload(filePath string, reader io.Reader, totalLength int64) error

	// upload tinyfile
	UploadTinyFile(filePath string, reader io.Reader) error

	// upload bigfile
	UploadBigFile(filePath string, reader io.Reader, totalLength int64) error

	// merge bigfile
	MergeBigFile(filePath string) error

	// get sign url
	GetSignURL(path string) string
}

type sgclient struct {
	token     string
	clusterId string
	user      string
	password  string
	orgId     string
	secEnv    string
	apiEnv    string
}

func New(clusterId, user, password, orgId, secEnv, apiEnv string) (Sgclient, error) {
	return &sgclient{
		clusterId: clusterId,
		user:      user,
		password:  password,
		orgId:     orgId,
		secEnv:    secEnv,
		apiEnv:    apiEnv,
	}, nil
}

type TokenResp struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data []struct {
		ClusterID   string `json:"clusterId"`
		ClusterName string `json:"clusterName"`
		Token       string `json:"token"`
	} `json:"data"`
}

type TokenValidResp struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

type FileMeta struct {
	Owner            string `json:"owner"`
	LastAccessTime   string `json:"lastAccessTime"`
	LastModifiedTime string `json:"lastModifiedTime"`
	CreationTime     string `json:"creationTime"`
	IsRegularFile    bool   `json:"isRegularFile"`
	Permission       string `json:"permission"`
	FileKey          int    `json:"fileKey"`
	Type             string `json:"type"`
	Path             string `json:"path"`
	Size             int64  `json:"size"`
	IsSymbolicLink   bool   `json:"isSymbolicLink"`
	Name             string `json:"name"`
	IsShare          bool   `json:"isShare"`
	PermissionAction struct {
		Read    bool `json:"read"`
		Allowed bool `json:"allowed"`
		Write   bool `json:"write"`
		Execute bool `json:"execute"`
	} `json:"permissionAction"`
	IsOther     bool   `json:"isOther"`
	IsDirectory bool   `json:"isDirectory"`
	Group       string `json:"group"`
}

type FileList struct {
	Total    int        `json:"total"`
	FileList []FileMeta `json:"fileList"`
	Children []struct {
		Path  string `json:"path"`
		ID    int    `json:"id"`
		Label string `json:"label"`
	} `json:"children"`
	Path         string      `json:"path"`
	KeyWord      interface{} `json:"keyWord"`
	ShareEnabled bool        `json:"shareEnabled"`
}

type FileListResp struct {
	Code string   `json:"code"`
	Data FileList `json:"data"`
	Msg  string   `json:"msg"`
}

type FileExistResp struct {
	Code string `json:"code"`
	Data struct {
		Exist bool `json:"exist"`
	} `json:"data"`
	Msg string `json:"msg"`
}

type MakeDirResp struct {
	Code string `json:"code"`
	Data string `json:"data"`
	Msg  string `json:"msg"`
}

type UploadResp struct {
	Code string      `json:"code"`
	Data interface{} `json:"data"`
	Msg  string      `json:"msg"`
}

const (
	CHUNK_SIZE       = 16 * 1024 * 1024
	READ_BUFFER_SIZE = 32 * 1024
	FILE_SHARD_LIMIT = 128 * 1024 * 1024
)

func (sg *sgclient) isTokenValid() (bool, error) {
	if sg.token == "" {
		return false, nil
	}

	//处理返回结果
	anyResponse, _, err := util.Run(15, 100, 4, "isTokenValid", func() (any, bool, error) {

		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			//生成client 参数为默认
			client := &http.Client{}
			defer client.CloseIdleConnections()
			url := sg.secEnv + "/ac/openapi/v2/tokens/state"
			request, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			return client.Do(request)
		})
		if err != nil {
			logger.Errorf("sugon---error=%s", err.Error())
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---isTokenValid bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})
	if anyResponse == nil {
		return false, fmt.Errorf("sugon---response nil")
	}
	if err != nil {
		return false, err
	}
	response := anyResponse.(*http.Response)
	if err != nil {
		return false, err
	}
	//返回的状态码
	if response.StatusCode/100 != 2 {
		return false, fmt.Errorf("sugon---isTokenValid bad resp status %s", response.Status)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var tokenValidResp TokenValidResp
	if err != nil {
		return false, err
	}
	err = json.Unmarshal((body), &tokenValidResp)
	if err != nil {
		return false, err
	}
	return tokenValidResp.Code == "0", nil
}

func (sg *sgclient) SetToken() error {
	//生成client 参数为默认
	valid, _ := sg.isTokenValid()
	if valid {
		return nil
	}

	anyResponse, _, err := util.Run(15, 100, 4, "SetToken", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			client := &http.Client{}
			defer client.CloseIdleConnections()
			url := sg.secEnv + "/ac/openapi/v2/tokens"
			request, err := http.NewRequest(http.MethodPost, url, nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("user", sg.user)
			request.Header.Add("password", sg.password)
			request.Header.Add("orgId", sg.orgId)
			return client.Do(request)
		})

		if err != nil {
			logger.Errorf("sugon---error=%s", err.Error())
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---SetToken bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})
	if err != nil {
		return err
	}
	response := anyResponse.(*http.Response)
	if err != nil {
		return err
	}
	//返回的状态码
	if response.StatusCode/100 != 2 {
		logger.Errorf("sugon---SetToken status %s", response.Status)
		return fmt.Errorf("SetToken bad resp status %s", response.Status)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var tokenResp TokenResp
	if err != nil {
		return err
	}
	err = json.Unmarshal((body), &tokenResp)
	if err != nil {
		return err
	}
	if tokenResp.Code != "0" {
		return fmt.Errorf("SetToken bad token return code %s %s", tokenResp.Code, tokenResp.Msg)
	}
	if len(tokenResp.Data) < 1 {
		logger.Errorf("sugon---SetToken empty token response list")
		return fmt.Errorf("SetToken empty token response list")
	}
	for _, cluster := range tokenResp.Data {
		if sg.clusterId == cluster.ClusterID {
			sg.token = tokenResp.Data[0].Token
			//logger.Errorf("sugon---SetToken get token %s", tokenResp.Data[0].Token)
			return nil
		}
	}
	logger.Errorf("sugon---SetToken SetToken get token for cluster id=%s failed", sg.clusterId)
	return fmt.Errorf("SetToken get token for cluster id=%s failed", sg.clusterId)

}

func (sg *sgclient) GetFileList(path, keyWord string, start, limit int64) (*FileList, error) {
	err := sg.SetToken()
	if err != nil {
		return nil, err
	}

	anyResponse, _, err := util.Run(15, 100, 4, "GetFileList", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/list"

			data := make(url.Values)
			data["start"] = []string{strconv.FormatInt(start, 10)}
			data["limit"] = []string{strconv.FormatInt(limit, 10)}
			if path != "" {
				data["path"] = []string{path}
			}
			if keyWord != "" {
				data["keyWord"] = []string{keyWord}
			}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodGet, uri.String(), nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)
		})
		if err != nil {
			logger.Errorf("sugon---error=%s", err.Error())
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---GetFileList bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})
	if anyResponse == nil {
		return nil, fmt.Errorf("sugon---response nil")
	}
	if err != nil {
		return nil, err
	}
	response := anyResponse.(*http.Response)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var fileListResp FileListResp
	err = json.Unmarshal((body), &fileListResp)
	if err != nil {
		return nil, err
	}
	if fileListResp.Code != "0" {
		if fileListResp.Code == "911020" {
			return nil, fmt.Errorf("NoSuchKey")
		}
		return nil, fmt.Errorf("GetFileList failed for path = %s, %s", path, fileListResp.Msg)
	}
	return &fileListResp.Data, nil
}

func (sg *sgclient) GetAllFile(path, keyWord string, start, limit int64, fileList *[]FileMeta, depth, maxDepth int) error {
	if depth >= maxDepth {
		return fmt.Errorf("dir depth exceed maxDepth error depth=%d maxDepth=%d", depth, maxDepth)
	}
	files, err := sg.GetFileList(path, keyWord, start, limit)
	if err != nil {
		logger.Errorf("sugon---GetAllFile GetFileList error %s", err.Error())
		return err
	}
	for _, file := range files.FileList {
		if file.IsDirectory {
			sg.GetAllFile(file.Path, keyWord, start, limit, fileList, depth+1, maxDepth)
		} else {
			*fileList = append(*fileList, file)
		}
	}
	dirMeta, err := sg.GetFileMeta(path)
	if err != nil {
		logger.Errorf("sugon---GetAllFile GetFileMeta error %s", err.Error())
		return err
	}
	*fileList = append(*fileList, *dirMeta)
	return nil
}

func (sg *sgclient) GetFileListRecursive(path, keyWord string, start, limit int64, maxDepth int) ([]FileMeta, error) {
	var fileList []FileMeta
	err := sg.GetAllFile(path, keyWord, start, limit, &fileList, 0, maxDepth)
	return fileList, err
}

func (sg *sgclient) GetFilesMeta(path, keyWord string, start, limit int64) ([]FileMeta, error) {
	fileList, err := sg.GetFileList(path, keyWord, start, limit)
	if err != nil {
		return nil, err
	}
	return fileList.FileList, nil
}

func (sg *sgclient) GetFileMeta(path string) (*FileMeta, error) {
	dir := filepath.Dir(path)
	file := filepath.Base(path)
	fileList, err := sg.GetFilesMeta(dir, file, 0, 1000)
	if err != nil {
		return nil, err
	}
	// keyword search is fuzzy, so need exactly file match
	for _, fileMeta := range fileList {
		if fileMeta.Name == file {
			return &fileMeta, nil
		}
	}
	return nil, fmt.Errorf("NoSuchKey")
}

func (sg *sgclient) FileExist(path string) (bool, error) {
	err := sg.SetToken()
	if err != nil {
		return false, err
	}

	anyResponse, _, err := util.Run(15, 100, 4, "FileExist", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/exist"

			data := make(url.Values)
			data["path"] = []string{path}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodPost, uri.String(), nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)

		})

		if err != nil {
			logger.Errorf("sugon---error=%s", err.Error())
			return nil, false, err
		}

		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}

		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---FileExist bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})

	if err != nil {
		return false, err
	}
	response := anyResponse.(*http.Response)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var fileExistResp FileExistResp
	if err != nil {
		return false, err
	}
	err = json.Unmarshal((body), &fileExistResp)
	if err != nil {
		return false, err
	}
	if fileExistResp.Code == "911020" {
		return false, nil
	} else if fileExistResp.Code != "0" {
		return false, fmt.Errorf("sugon---FileExist check failed, path=%s, Code=%s, Message=%s", path, fileExistResp.Code, fileExistResp.Msg)
	} else {
		return fileExistResp.Data.Exist, nil
	}
}

func (sg *sgclient) CreateDir(path string) (bool, error) {
	err := sg.SetToken()
	if err != nil {
		return false, err
	}

	anyResponse, _, err := util.Run(15, 100, 4, "CreateDir", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {

			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/mkdir"

			data := make(url.Values)
			data["path"] = []string{path}
			data["createParents"] = []string{"true"}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodPost, uri.String(), nil)
			if err != nil {
				return nil, err
			}

			request.Header.Add("token", sg.token)
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)

		})

		if err != nil {
			logger.Errorf("sugon---error=%s", err.Error())
			return nil, false, err
		}

		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---CreateDir bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})

	if err != nil {
		return false, err
	}
	response := anyResponse.(*http.Response)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var makeDirResp MakeDirResp
	if err != nil {
		return false, err
	}
	err = json.Unmarshal((body), &makeDirResp)
	if err != nil {
		return false, err
	}

	if makeDirResp.Code != "0" && makeDirResp.Code != "911021" {
		return false, fmt.Errorf("sugon---CreateDir failed, path=%s, Code=%s, Message=%s", path, makeDirResp.Code, makeDirResp.Msg)
	}

	return true, nil
}

func (sg *sgclient) DeleteFile(path string) (bool, error) {
	err := sg.SetToken()
	if err != nil {
		return false, err
	}

	anyResponse, _, err := util.Run(15, 100, 4, "DeleteFile", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {

			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/remove"

			data := make(url.Values)
			data["paths"] = []string{path}
			data["recursive"] = []string{"true"}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodPost, uri.String(), nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)

		})
		if err != nil {
			logger.Errorf("sugon---error=%s", err.Error())
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---DeleteFile bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})
	if err != nil {
		return false, err
	}
	response := anyResponse.(*http.Response)

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var makeDirResp MakeDirResp
	if err != nil {
		return false, err
	}
	err = json.Unmarshal((body), &makeDirResp)
	if err != nil {
		return false, err
	}

	if makeDirResp.Code != "0" {
		return false, fmt.Errorf("sugon---DeleteFile failed, path=%s, Code=%s, Message=%s", path, makeDirResp.Code, makeDirResp.Msg)
	}

	return true, nil
}

func (sg *sgclient) Download(path string) (io.ReadCloser, error) {
	err := sg.SetToken()
	if err != nil {
		return nil, err
	}

	anyResponse, _, err := util.Run(15, 100, 4, "Download", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/download"
			data := make(url.Values)
			data["path"] = []string{path}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodGet, uri.String(), nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)
		})

		if err != nil {
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon nil response err")
		}

		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---Download bad resp status %s", response.StatusCode)
		}
		return response, false, err
	})
	if err != nil {
		return nil, err
	}
	response := anyResponse.(*http.Response)
	return response.Body, nil
}

func (sg *sgclient) Upload(filePath string, reader io.Reader, totalLength int64) error {
	if totalLength < FILE_SHARD_LIMIT {
		logger.Infof("sugon&&&start upload by UploadTinyFile %dB", totalLength)
		return sg.UploadTinyFile(filePath, reader)
	} else {
		logger.Infof("sugon&&&start upload by UploadBigFile %dB", totalLength)
		err := sg.UploadBigFile(filePath, reader, totalLength)
		if err != nil {
			return err
		}
		logger.Infof("sugon&&&start merge file shards by MergeBigFile %dB", totalLength)
		return sg.MergeBigFile(filePath)
	}
}

func (sg *sgclient) UploadTinyFile(filePath string, reader io.Reader) error {
	err := sg.SetToken()
	if err != nil {
		return err
	}
	_, _, err = util.Run(15, 100, 4, "UploadTinyFile", func() (any, bool, error) {
		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			bodyBuf := &bytes.Buffer{}
			bodyWriter := multipart.NewWriter(bodyBuf)
			fileName := filepath.Base(filePath)
			fileDir := filepath.Dir(filePath)
			fileWriter, err := bodyWriter.CreateFormFile("file", fileName)
			_, err = io.Copy(fileWriter, reader)
			if err != nil {
				return nil, err
			}
			contentType := bodyWriter.FormDataContentType()
			bodyWriter.Close()
			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/upload"
			data := make(url.Values)
			data["path"] = []string{fileDir}
			data["cover"] = []string{"cover"}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodPost, uri.String(), bodyBuf)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			request.Header.Add("Content-Type", contentType)
			request.Header.Add("Content-Type", "multipart/form-data")
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)
		})

		if err != nil {
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---Upload TinyFile bad resp status %s", response.StatusCode)
		}
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		var uploadResp UploadResp
		if err != nil {
			return nil, false, err
		}
		err = json.Unmarshal((body), &uploadResp)
		if err != nil {
			return nil, false, err
		}

		if uploadResp.Code != "0" {
			return nil, false, fmt.Errorf("sugon---Upload failed, path=%s, Code=%s, Message=%s", filePath, uploadResp.Code, uploadResp.Msg)
		}
		return nil, false, err
	})
	return err
}

func (sg *sgclient) UploadBigFile(filePath string, reader io.Reader, totalLength int64) error {
	err := sg.SetToken()
	if err != nil {
		return err
	}

	fileName := filepath.Base(filePath)
	fileDir := filepath.Dir(filePath)

	chunkCount := int(math.Ceil(float64(totalLength) / float64(CHUNK_SIZE)))
	chunkNumber := 1
	for {
		n := 0
		dataBuffer := make([]byte, 0)
		pipeBuffer := make([]byte, READ_BUFFER_SIZE)
		for {
			nn, err := reader.Read(pipeBuffer)
			if err != nil && err != io.EOF {
				logger.Errorf(err.Error())
				return err
			}
			if nn == 0 {
				break
			}
			dataBuffer = append(dataBuffer, pipeBuffer...)
			n += nn
			if nn < READ_BUFFER_SIZE || n >= CHUNK_SIZE {
				break
			}
		}
		if n == 0 {
			break
		}

		_, _, err = util.Run(15, 100, 4, "UploadBigFile", func() (any, bool, error) {

			response, err := util.LoopDoRequest(func() (*http.Response, error) {
				bodyBuf := &bytes.Buffer{}
				bodyWriter := multipart.NewWriter(bodyBuf)
				fileWriter, err := bodyWriter.CreateFormFile("file", fileName)
				length, err := fileWriter.Write(dataBuffer[:n])
				if err != nil {
					return nil, err
				}
				contentType := bodyWriter.FormDataContentType()
				bodyWriter.Close()
				//生成要访问的url
				requestUrl := sg.apiEnv + "/efile/openapi/v2/file/burst"

				data := make(url.Values)
				data["path"] = []string{fileDir}
				data["filename"] = []string{fileName}
				data["relativePath"] = []string{fileName}
				data["cover"] = []string{"cover"}
				data["totalSize"] = []string{strconv.FormatInt(totalLength, 10)}
				data["chunkSize"] = []string{strconv.FormatInt(int64(CHUNK_SIZE), 10)}
				data["totalChunks"] = []string{strconv.FormatInt(int64(chunkCount), 10)}
				data["currentChunkSize"] = []string{strconv.FormatInt(int64(length), 10)}
				data["chunkNumber"] = []string{strconv.FormatInt(int64(chunkNumber), 10)}

				uri, _ := url.Parse(requestUrl)
				values := uri.Query()
				if values != nil {
					for k, v := range values {
						data[k] = v
					}
				}
				uri.RawQuery = data.Encode()
				//提交请求
				request, err := http.NewRequest(http.MethodPost, uri.String(), bodyBuf)
				if err != nil {
					return nil, err
				}
				request.Header.Add("token", sg.token)
				request.Header.Add("Content-Type", contentType)
				request.Header.Add("Content-Type", "multipart/form-data")
				client := &http.Client{}
				defer client.CloseIdleConnections()

				return client.Do(request)
			})

			//处理返回结果

			if err != nil {
				logger.Errorf("sugon---UploadBigFile error=%s", err.Error())
				logger.Errorf("response", response.StatusCode)
				return nil, false, err
			}
			if response == nil {
				logger.Errorf("sugon---UploadBigFile response nil")
				return nil, false, fmt.Errorf("sugon---response nil")
			}
			if response.StatusCode/100 != 2 {
				err = fmt.Errorf("sugon---Upload bad resp status %s", response.StatusCode)
			}
			defer response.Body.Close()

			body, err := io.ReadAll(response.Body)
			var uploadResp UploadResp
			if err != nil {
				logger.Errorf("sugon---UploadBigFile error = %s", err.Error())
				return nil, false, err
			}
			err = json.Unmarshal((body), &uploadResp)
			if err != nil {
				return nil, false, err
			}
			if uploadResp.Code != "0" {
				return nil, false, fmt.Errorf("sugon---Upload failed, path=%s, totalLength=%d, currentChunkSize=%d"+
					", chunkSize=%d, Code=%s, Message=%s, chunkNumber=%d, dataBuffer=%d, pipeBuffer=%d",
					filePath, totalLength, n, CHUNK_SIZE, uploadResp.Code, uploadResp.Msg, chunkNumber, len(dataBuffer), len(pipeBuffer))
			}
			return response, false, err
		})
		if err != nil {
			return err
		}
		chunkNumber += 1
	}
	return nil
}

func (sg *sgclient) MergeBigFile(filePath string) error {
	err := sg.SetToken()
	if err != nil {
		return err
	}

	fileName := filepath.Base(filePath)
	fileDir := filepath.Dir(filePath)

	_, _, err = util.Run(15, 100, 4, "MergeBigFile", func() (any, bool, error) {

		response, err := util.LoopDoRequest(func() (*http.Response, error) {
			//生成要访问的url
			requestUrl := sg.apiEnv + "/efile/openapi/v2/file/merge"
			data := make(url.Values)
			data["path"] = []string{fileDir}
			data["filename"] = []string{fileName}
			data["relativePath"] = []string{fileName}
			data["cover"] = []string{"cover"}
			uri, _ := url.Parse(requestUrl)
			values := uri.Query()
			if values != nil {
				for k, v := range values {
					data[k] = v
				}
			}
			uri.RawQuery = data.Encode()
			//提交请求
			request, err := http.NewRequest(http.MethodPost, uri.String(), nil)
			if err != nil {
				return nil, err
			}
			request.Header.Add("token", sg.token)
			client := &http.Client{}
			defer client.CloseIdleConnections()
			//处理返回结果
			return client.Do(request)
		})

		if err != nil {
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("sugon---response nil")
		}
		if response.StatusCode/100 != 2 {
			err = fmt.Errorf("sugon---MergeBigFile bad resp status %s", response.StatusCode)
		}
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, false, err
		}
		var uploadResp UploadResp
		err = json.Unmarshal((body), &uploadResp)
		if err != nil {
			return nil, false, err
		}
		if uploadResp.Code != "0" {
			return nil, false, fmt.Errorf("sugon---Merge failed, path=%s, Code=%s, Message=%s", filePath, uploadResp.Code, uploadResp.Msg)
		}
		return response, false, err
	})
	return err
}

func (sg *sgclient) GetSignURL(path string) string {
	requestUrl := sg.apiEnv + "/efile/openapi/v2/file/download"
	data := make(url.Values)
	data["path"] = []string{path}
	data["token"] = []string{sg.token}
	uri, _ := url.Parse(requestUrl)
	values := uri.Query()
	if values != nil {
		for k, v := range values {
			data[k] = v
		}
	}
	uri.RawQuery = data.Encode()
	return uri.String()
}
