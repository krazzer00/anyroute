package anyconnect

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// challengeForm — разбор challenge-ответа: auth-request с формой, где есть
// <input> для второго фактора. DTD не разбирает <input>, поэтому сырое тело
// ответа парсится отдельно.
type challengeForm struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	// <opaque> challenge-ответа отличается от init: ASA кладёт в него
	// <auth-handle>, которым связывает ответ с выданным challenge. Его нужно
	// вернуть дословно, поэтому храним сырое содержимое.
	Opaque struct {
		Inner string `xml:",innerxml"`
	} `xml:"opaque"`
	Auth struct {
		ID string `xml:"id,attr"`
		// ASA отдаёт текст как шаблон, подстановки — в атрибутах:
		// <message id="2" param1="Введите OTP-код">%s</message>.
		Message struct {
			Value  string `xml:",chardata"`
			Param1 string `xml:"param1,attr"`
			Param2 string `xml:"param2,attr"`
		} `xml:"message"`
		Form struct {
			Action string `xml:"action,attr"`
			Inputs []struct {
				Type  string `xml:"type,attr"`
				Name  string `xml:"name,attr"`
				Label string `xml:"label,attr"`
			} `xml:"input"`
		} `xml:"form"`
	} `xml:"auth"`
}

// Challenge — запрос второго фактора от сервера.
type Challenge struct {
	Message string // текст для пользователя (уже с подстановками)
	Label   string // подпись поля ввода из формы
	// Retry — сервер отклонил предыдущий код и выдал новую форму.
	Retry bool

	action      string
	field       string
	hasUsername bool
	opaque      string
}

// detectChallenge определяет, является ли тело ответа challenge-формой 2FA.
// Признаки: type="auth-request" и (auth id="challenge" ИЛИ форма с <input>
// для кода — любое поле, кроме полей первичного логина).
func detectChallenge(body []byte) (*Challenge, bool) {
	var cf challengeForm
	if err := xml.Unmarshal(body, &cf); err != nil {
		return nil, false
	}
	if cf.Type != "auth-request" {
		return nil, false
	}
	field, label := cf.codeField()
	if cf.Auth.ID != "challenge" && field == "" {
		return nil, false
	}
	return &Challenge{
		Message:     formatServerMessage(cf.Auth.Message.Value, cf.Auth.Message.Param1, cf.Auth.Message.Param2),
		Label:       label,
		action:      cf.Auth.Form.Action,
		field:       field,
		hasUsername: cf.hasInput("username"),
		opaque:      strings.TrimSpace(cf.Opaque.Inner),
	}, true
}

func (cf *challengeForm) hasInput(name string) bool {
	for _, in := range cf.Auth.Form.Inputs {
		if strings.EqualFold(in.Name, name) {
			return true
		}
	}
	return false
}

// codeField — имя и подпись поля, в котором сервер ждёт код.
func (cf *challengeForm) codeField() (string, string) {
	for _, in := range cf.Auth.Form.Inputs {
		if strings.EqualFold(in.Type, "submit") || strings.EqualFold(in.Type, "hidden") {
			continue
		}
		switch strings.ToLower(in.Name) {
		case "username", "password", "group_list", "":
		default:
			return in.Name, strings.TrimSpace(in.Label)
		}
	}
	return "", ""
}

// codeElement отображает имя поля формы на имя XML-элемента ответа.
// ASA называет поле answer (реже whichpin/new_password), но значение ждёт в
// <password> — так же поступает OpenConnect (xmlpost_append_form_opts).
// Отправка <answer> приводит к «Login failed.» на верный код.
func codeElement(field string) string {
	switch strings.ToLower(field) {
	case "", "answer", "whichpin", "new_password":
		return "password"
	default:
		return field
	}
}

// formatServerMessage приводит сообщение ASA к читаемому виду: шаблон может
// не содержать %s, быть пустым или содержать несколько подстановок.
// Безусловный Sprintf давал литеральное "%s" и "%!(EXTRA string=)".
func formatServerMessage(tpl, param1, param2 string) string {
	tpl = strings.TrimSpace(tpl)
	p1 := strings.TrimSpace(param1)
	p2 := strings.TrimSpace(param2)
	if tpl == "" {
		return strings.TrimSpace(p1 + " " + p2)
	}
	n := strings.Count(tpl, "%s")
	if n == 0 {
		return tpl
	}
	args := make([]any, n)
	for i := range args {
		switch i {
		case 0:
			args[i] = p1
		case 1:
			args[i] = p2
		default:
			args[i] = ""
		}
	}
	return strings.TrimSpace(fmt.Sprintf(tpl, args...))
}
